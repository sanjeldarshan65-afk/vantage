import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { EngagementStore } from '../src/core/store.js';
import { engagementDoc, tempDir } from './_helpers.js';

function finding(overrides = {}) {
  return {
    check: 'web.headers.missing-hsts',
    title: 'HSTS not enabled',
    severity: 'medium',
    confidence: 'confirmed',
    target: 'https://app.example.com/',
    description: 'The response has no Strict-Transport-Security header.',
    impact: 'Downgrade attacks are easier.',
    remediation: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    observed: [{ key: 'strict-transport-security', value: 'absent' }],
    evidence: ['ev_one'],
    references: ['https://owasp.org/www-project-secure-headers/'],
    cwe: ['CWE-319'],
    owasp: ['A05:2021'],
    ...overrides
  };
}

async function withStore(fn) {
  const root = await tempDir();
  const engagementsRoot = path.join(root, 'engagements');
  const store = await EngagementStore.create(engagementDoc(), { engagementsRoot });
  try {
    await fn({ store, root, engagementsRoot });
  } finally {
    await store.close();
    await fs.rm(root, { recursive: true, force: true });
  }
}

test('create, open, exists and list', async () => {
  const root = await tempDir();
  const engagementsRoot = path.join(root, 'engagements');
  try {
    const store = await EngagementStore.create(engagementDoc({ id: 'eng-one' }), { engagementsRoot });
    await store.addFinding(finding());
    await store.close();

    assert.equal(await EngagementStore.exists('eng-one', { engagementsRoot }), true);
    assert.equal(await EngagementStore.exists('missing', { engagementsRoot }), false);

    const reopened = await EngagementStore.open('eng-one', { engagementsRoot });
    assert.equal(reopened.engagement.id, 'eng-one');
    assert.equal(reopened.findings.length, 1);
    assert.equal(reopened.scope.mode, 'safe');
    await reopened.close();

    const listed = await EngagementStore.list({ engagementsRoot });
    assert.equal(listed.length, 1);
    assert.equal(listed[0].id, 'eng-one');
    assert.equal(listed[0].findings, 1);

    await assert.rejects(() => EngagementStore.create(engagementDoc({ id: 'eng-one' }), { engagementsRoot }), /already exists/);
    const overwritten = await EngagementStore.create(engagementDoc({ id: 'eng-one' }), { engagementsRoot, overwrite: true });
    assert.equal(overwritten.findings.length, 0);
    await overwritten.close();
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test('findings dedupe, merge evidence and reopen when fixed', async () => {
  await withStore(async ({ store }) => {
    const first = await store.addFinding(finding());
    assert.equal(first.occurrences, 1);
    assert.equal(first.status, 'open');
    assert.equal(first.severityRank, 2);

    const second = await store.addFinding(finding({ evidence: ['ev_two'], severity: 'high' }));
    assert.equal(second.id, first.id, 'same check+target+observed must merge');
    assert.equal(second.occurrences, 2);
    assert.equal(second.severity, 'high');
    assert.deepEqual(second.evidence.sort(), ['ev_one', 'ev_two']);

    await store.updateFinding(first.id, { status: 'fixed', note: 'patched' });
    assert.equal(store.getFinding(first.id).status, 'fixed');
    const reobserved = await store.addFinding(finding());
    assert.equal(reobserved.status, 'open', 'a re-observation reopens a fixed finding');
    assert.equal(reobserved.history.at(-1).event, 'reopened');
  });
});

test('updateFinding validates status and keeps history', async () => {
  await withStore(async ({ store }) => {
    const created = await store.addFinding(finding());
    const updated = await store.updateFinding(created.id, { status: 'accepted', note: 'risk accepted by client' });
    assert.equal(updated.status, 'accepted');
    const history = updated.history.at(-1);
    assert.equal(history.from, 'open');
    assert.equal(history.to, 'accepted');
    assert.equal(history.note, 'risk accepted by client');
    assert.equal(await store.updateFinding('nope', { status: 'fixed' }), null);
    await assert.rejects(() => store.updateFinding(created.id, { status: 'exploited' }), /Unknown finding status/);
  });
});

test('listFindings filters, searches and sorts by severity', async () => {
  await withStore(async ({ store }) => {
    await store.addFinding(finding({ check: 'web.a.x', title: 'Alpha', severity: 'low' }));
    await store.addFinding(finding({ check: 'web.b.y', title: 'Bravo', severity: 'critical', observed: [{ key: 'k', value: 'v' }] }));
    await store.addFinding(finding({ check: 'web.c.z', title: 'Charlie', severity: 'medium', target: 'https://other.example.com/' }));
    const all = store.listFindings();
    assert.deepEqual(all.map((f) => f.title), ['Bravo', 'Charlie', 'Alpha']);
    assert.equal(store.listFindings({ severity: 'medium' }).length, 1);
    assert.equal(store.listFindings({ search: 'other.example' }).length, 1);
    assert.equal(store.listFindings({ status: 'open' }).length, 3);
    assert.equal(store.listFindings({ status: 'fixed' }).length, 0);
    assert.equal(store.listFindings({ check: 'web.a.x' }).length, 1);
    assert.equal(store.listFindings({ sort: 'title' })[0].title, 'Alpha');
  });
});

test('assets dedupe, resolve parents and feed coverage', async () => {
  await withStore(async ({ store }) => {
    const domain = await store.addAsset({ type: 'domain', value: 'example.com' });
    const sub = await store.addAsset({ type: 'subdomain', value: 'app.example.com', parent: 'example.com' });
    assert.equal(sub.parentId, domain.id);
    const same = await store.addAsset({ type: 'subdomain', value: 'app.example.com', attributes: { addresses: ['10.0.0.1'] } });
    assert.equal(same.id, sub.id, 'type+value is the asset identity');
    assert.deepEqual(same.attributes.addresses, ['10.0.0.1']);

    const endpoint = await store.addAsset({ type: 'endpoint', value: 'https://app.example.com/', parent: { type: 'subdomain', value: 'app.example.com' } });
    assert.equal(endpoint.parentId, sub.id);

    let coverage = store.coverage();
    assert.equal(coverage.total, 3);
    assert.equal(coverage.tested, 0);
    assert.equal(coverage.percentTested, 0);

    await store.touchAsset(endpoint.id, 'tested');
    coverage = store.coverage();
    assert.equal(coverage.tested, 1);
    assert.equal(coverage.byType.endpoint.tested, 1);
    assert.equal(coverage.byType.domain.untested, 1);

    await assert.rejects(() => store.addAsset({ type: 'nonsense', value: 'x' }), /Unknown asset type/);
    await assert.rejects(() => store.addAsset({ type: 'ip', value: '' }), /needs a value/);
  });
});

test('activity, runs and snapshot', async () => {
  await withStore(async ({ store }) => {
    await store.note('started recon');
    const activity = store.activity(10);
    assert.equal(activity.at(-1).message, 'started recon');

    await store.addFinding(finding({ severity: 'critical' }));
    await store.addAsset({ type: 'ip', value: '10.0.0.1' });
    const run = await store.saveRun({ id: 'run_abc', startedAt: '2026-01-01T00:00:00.000Z', status: 'completed', stats: { findings: 1 } });
    assert.equal(run.engagementId, store.id);
    assert.equal(store.listRuns().length, 1);
    assert.equal(store.getRun('run_abc').status, 'completed');

    const snapshot = await store.snapshot();
    assert.equal(snapshot.engagement.id, store.id);
    assert.equal(snapshot.summary.total, 1);
    assert.equal(snapshot.summary.bySeverity.critical, 1);
    assert.equal(snapshot.assets.length, 1);
    assert.equal(snapshot.runs.length, 1);
    assert.ok(snapshot.generatedAt);
    assert.ok(snapshot.scope.targets.length > 0);
    assert.equal(snapshot.coverage.total, 1);
    assert.equal(snapshot.audit.total, 0);
  });
});

test('reconcile marks absent findings and reopens observed ones', async () => {
  await withStore(async ({ store }) => {
    const stillThere = await store.addFinding(finding({ check: 'web.a.x', title: 'Still there' }));
    const gone = await store.addFinding(finding({ check: 'web.b.y', title: 'Gone', observed: [{ key: 'k', value: 'v' }] }));
    const result = await store.reconcile([stillThere.dedupeKey]);
    assert.deepEqual(result, { markedNotObserved: 1, reopened: 0 });
    assert.equal(store.getFinding(gone.id).status, 'not_observed');
    assert.equal(store.getFinding(stillThere.id).status, 'open');

    const again = await store.reconcile([stillThere.dedupeKey, gone.dedupeKey]);
    assert.equal(again.reopened, 1);
    assert.equal(store.getFinding(gone.id).status, 'open');
  });
});

test('persistence survives reopening and evidence is retrievable', async () => {
  const root = await tempDir();
  const engagementsRoot = path.join(root, 'engagements');
  try {
    const store = await EngagementStore.create(engagementDoc({ id: 'persist' }), { engagementsRoot });
    await store.addFinding(finding());
    await store.addAsset({ type: 'service', value: 'app.example.com:443', attributes: { port: 443, protocol: 'tcp' } });
    await store.flush();
    const evidence = await store.evidence.save({
      runId: null,
      module: 'web.headers',
      request: { method: 'GET', url: 'https://app.example.com/', headers: { authorization: 'Bearer x' } },
      response: { status: 200, statusText: 'OK', headers: { 'set-cookie': ['sid=secret; Secure'] }, setCookie: ['sid=secret; Secure'], body: 'hello', elapsedMs: 4 }
    });
    await store.close();

    const reopened = await EngagementStore.open('persist', { engagementsRoot });
    assert.equal(reopened.findings.length, 1);
    assert.equal(reopened.assets.length, 1);
    const stored = await reopened.evidence.get(evidence.id);
    assert.ok(stored, 'evidence must resolve by id');
    assert.equal(stored.response.bodyPreview, 'hello');
    const storedJson = JSON.stringify(stored);
    assert.ok(!storedJson.includes('Bearer x'), 'authorization header must be redacted');
    assert.ok(!storedJson.includes('secret'), 'cookie value must be redacted');
    assert.ok(storedJson.includes('Secure'), 'cookie attributes stay readable');
    await reopened.close();
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});
