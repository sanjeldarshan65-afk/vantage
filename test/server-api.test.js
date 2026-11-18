import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { createServer } from '../server/index.js';
import { EventBus } from '../server/sse.js';
import { EngagementStore } from '../src/core/store.js';
import { silentLogger } from '../src/core/log.js';
import { engagementDoc, tempDir } from './_helpers.js';

const TOKEN = 'test-token-0123456789abcdef';

let root;
let engagementsRoot;
let fixtureStore;
let emptyStore;
let dashboard;
let baseUrl;
let port;
let bus;
let findingCritical;
let findingMedium;
let knownEvidenceId;

function httpRequest(urlPath, { method = 'GET', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path: urlPath, method, headers: { ...headers } },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json = null;
          try {
            json = JSON.parse(text);
          } catch {
            json = null;
          }
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
      }
    );
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function patchFinding(findingId, payload, token) {
  const headers = { 'content-type': 'application/json' };
  if (token !== undefined) headers['x-vantage-token'] = token;
  return httpRequest(`/api/engagements/dash-fixture/findings/${findingId}`, {
    method: 'PATCH',
    headers,
    body: JSON.stringify(payload)
  });
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
      timer.unref?.();
    })
  ]);
}

/** Open an SSE stream and resolve once the first frame and later bus events arrive. */
function openEventStream(urlPath) {
  const state = { status: null, headers: null, data: '', firstFrame: false };
  let resolveFirst;
  let rejectFirst;
  const first = new Promise((resolve, reject) => {
    resolveFirst = resolve;
    rejectFirst = reject;
  });
  let resolveEvent;
  const eventSeen = new Promise((resolve) => {
    resolveEvent = resolve;
  });
  const req = http.get({ hostname: '127.0.0.1', port, path: urlPath }, (res) => {
    state.status = res.statusCode;
    state.headers = res.headers;
    res.setEncoding('utf8');
    res.on('data', (chunk) => {
      state.data += chunk;
      if (!state.firstFrame && state.data.includes('\n\n')) {
        state.firstFrame = true;
        resolveFirst();
      }
      if (state.data.includes('event: run:start')) resolveEvent();
    });
    res.on('error', () => {});
  });
  req.on('error', (error) => {
    if (error?.code !== 'ECONNRESET' && !state.firstFrame) rejectFirst(error);
  });
  return { state, first, eventSeen, close: () => req.destroy() };
}

before(async () => {
  root = await tempDir('vantage-server-test-');
  engagementsRoot = path.join(root, 'engagements');

  fixtureStore = await EngagementStore.create(engagementDoc({ id: 'dash-fixture' }), {
    engagementsRoot,
    logger: silentLogger()
  });
  findingCritical = await fixtureStore.addFinding({
    check: 'web.headers.missing-hsts',
    title: 'HSTS not enabled',
    severity: 'critical',
    confidence: 'confirmed',
    target: 'http://127.0.0.1:8080/',
    description: 'The response has no Strict-Transport-Security header.',
    impact: 'Protocol downgrade attacks are easier.',
    remediation: 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains.',
    observed: [{ key: 'strict-transport-security', value: 'absent' }],
    evidence: ['ev_fixture'],
    references: ['https://owasp.org/www-project-secure-headers/'],
    cwe: ['CWE-319'],
    owasp: ['A05:2021']
  });
  findingMedium = await fixtureStore.addFinding({
    check: 'web.cookies.missing-secure',
    title: 'Session cookie without Secure',
    severity: 'medium',
    confidence: 'likely',
    target: 'http://127.0.0.1:8080/login',
    description: 'A session cookie is set without the Secure flag.',
    impact: 'The cookie can be sent over cleartext HTTP.',
    remediation: 'Set the Secure attribute on all session cookies.',
    observed: [{ key: 'set-cookie', value: 'sid=abc123' }]
  });
  const asset = await fixtureStore.addAsset({
    type: 'endpoint',
    value: 'http://127.0.0.1:8080/',
    attributes: { scheme: 'http', port: 8080 }
  });
  await fixtureStore.touchAsset(asset, 'tested');
  await fixtureStore.saveRun({
    id: 'run_fixture1',
    startedAt: '2026-01-01T00:00:00.000Z',
    endedAt: '2026-01-01T00:00:03.000Z',
    elapsedMs: 3000,
    status: 'completed',
    mode: 'safe',
    phases: ['recon', 'web'],
    target: { url: 'http://127.0.0.1:8080/' },
    modules: [{ id: 'web.headers', status: 'done' }],
    stats: { modules: 2, findings: 2, assets: 1, requests: 4, denials: 0, evidence: 2 }
  });
  const evidence = await fixtureStore.evidence.save({
    runId: 'run_fixture1',
    module: 'web.headers',
    request: { method: 'GET', url: 'http://127.0.0.1:8080/', headers: { authorization: 'Bearer super-secret' } },
    response: {
      status: 200,
      statusText: 'OK',
      headers: { server: 'test-fixture' },
      body: 'fixture body',
      elapsedMs: 4
    }
  });
  knownEvidenceId = evidence.id;
  await fixtureStore.flush();

  emptyStore = await EngagementStore.create(engagementDoc({ id: 'dash-empty' }), {
    engagementsRoot,
    logger: silentLogger()
  });
  await emptyStore.flush();

  bus = new EventBus();
  dashboard = createServer({ dataDir: root, token: TOKEN, logger: silentLogger(), bus });
  baseUrl = await dashboard.start(0);
  port = Number(new URL(baseUrl).port);
});

after(async () => {
  await dashboard?.close();
  await fixtureStore?.close();
  await emptyStore?.close();
  await fs.rm(root, { recursive: true, force: true });
});

test('server binds loopback only and reports a 127.0.0.1 URL', () => {
  const address = dashboard.server.address();
  assert.equal(address.address, '127.0.0.1');
  assert.match(baseUrl, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.equal(dashboard.url, baseUrl);
  assert.equal(typeof dashboard.token, 'string');
  assert.ok(dashboard.token.length >= 16);
  assert.ok(dashboard.bus instanceof EventBus);
});

test('GET /api/health returns server state', async () => {
  const res = await httpRequest('/api/health');
  assert.equal(res.status, 200);
  assert.equal(res.headers['cache-control'], 'no-store');
  assert.equal(res.json.ok, true);
  assert.equal(res.json.name, 'vantage');
  assert.ok(res.json.ts);
  assert.equal(res.json.live.engine.running, false);
  assert.ok(res.json.live.startedAt);
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
});

test('security headers are set on every response', async () => {
  for (const urlPath of ['/', '/app.js', '/api/health']) {
    const res = await httpRequest(urlPath);
    const csp = res.headers['content-security-policy'];
    assert.ok(csp, `CSP missing on ${urlPath}`);
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /img-src 'self' data:/);
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
  }
});

test('GET /api/engagements lists summaries with severity counts', async () => {
  const res = await httpRequest('/api/engagements');
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.json), 'engagements endpoint returns an array');
  const fixture = res.json.find((entry) => entry.id === 'dash-fixture');
  assert.ok(fixture, 'fixture engagement is listed');
  assert.equal(fixture.name, 'Test Engagement');
  assert.equal(fixture.counts.findings, 2);
  assert.equal(fixture.counts.bySeverity.critical, 1);
  assert.equal(fixture.counts.bySeverity.medium, 1);
  assert.equal(fixture.counts.assets, 1);
  assert.equal(fixture.coverage.percentTested, 100);
  assert.ok(fixture.lastRun, 'lastRun summary is included');
  assert.equal(fixture.lastRun.id, 'run_fixture1');
  assert.ok(res.json.some((entry) => entry.id === 'dash-empty'));
});

test('GET /api/engagements/:id returns detail without heavy arrays', async () => {
  const res = await httpRequest('/api/engagements/dash-fixture');
  assert.equal(res.status, 200);
  assert.equal(res.json.engagement.id, 'dash-fixture');
  assert.equal(res.json.engagement.authorizationRef, 'UNIT-TEST-AUTHORIZATION');
  assert.equal(res.json.counts.findings, 2);
  assert.equal(res.json.counts.bySeverity.critical, 1);
  assert.equal(res.json.counts.assets, 1);
  assert.equal(res.json.counts.evidence, 1);
  assert.equal(res.json.counts.runs, 1);
  assert.equal(res.json.counts.requests, 4);
  assert.ok(Array.isArray(res.json.scope.targets));
  assert.ok(res.json.coverage);
  assert.ok(Array.isArray(res.json.runs));
  assert.equal(res.json.runs[0].id, 'run_fixture1');
  assert.equal(res.json.findings, undefined, 'findings array is not part of the overview payload');
  assert.equal(res.json.assets, undefined, 'assets array is not part of the overview payload');
});

test('GET /api/engagements/:id/findings filters by severity, status and search', async () => {
  const critical = await httpRequest('/api/engagements/dash-fixture/findings?severity=critical');
  assert.equal(critical.status, 200);
  assert.equal(critical.json.findings.length, 1);
  assert.equal(critical.json.findings[0].id, findingCritical.id);
  assert.equal(critical.json.findings[0].observed[0].key, 'strict-transport-security');

  const all = await httpRequest('/api/engagements/dash-fixture/findings');
  assert.equal(all.json.findings.length, 2);
  assert.equal(all.json.findings[0].severity, 'critical', 'default sort is severity-first');

  const open = await httpRequest('/api/engagements/dash-fixture/findings?status=open');
  assert.equal(open.json.findings.length, 2);

  const search = await httpRequest('/api/engagements/dash-fixture/findings?search=cookie');
  assert.equal(search.json.findings.length, 1);
  assert.equal(search.json.findings[0].id, findingMedium.id);

  const none = await httpRequest('/api/engagements/dash-fixture/findings?status=fixed');
  assert.equal(none.json.findings.length, 0);
});

test('GET /api/engagements/:id/findings/:fid returns one finding or 404', async () => {
  const res = await httpRequest(`/api/engagements/dash-fixture/findings/${findingCritical.id}`);
  assert.equal(res.status, 200);
  assert.equal(res.json.id, findingCritical.id);
  assert.equal(res.json.description, 'The response has no Strict-Transport-Security header.');

  const missing = await httpRequest('/api/engagements/dash-fixture/findings/fnd_nope');
  assert.equal(missing.status, 404);
  assert.equal(missing.json.code, 'not_found');
  assert.ok(missing.json.error);
});

test('GET /api/engagements/:id/assets returns assets and coverage', async () => {
  const res = await httpRequest('/api/engagements/dash-fixture/assets');
  assert.equal(res.status, 200);
  assert.equal(res.json.assets.length, 1);
  assert.equal(res.json.assets[0].type, 'endpoint');
  assert.equal(res.json.assets[0].state, 'tested');
  assert.equal(res.json.coverage.percentTested, 100);
});

test('GET /api/engagements/:id/runs returns run summaries', async () => {
  const res = await httpRequest('/api/engagements/dash-fixture/runs');
  assert.equal(res.status, 200);
  assert.ok(Array.isArray(res.json));
  assert.equal(res.json.length, 1);
  assert.equal(res.json[0].id, 'run_fixture1');
  assert.equal(res.json[0].status, 'completed');
  assert.equal(res.json[0].stats.requests, 4);

  const empty = await httpRequest('/api/engagements/dash-empty/runs');
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.json, []);

  const detail = await httpRequest('/api/engagements/dash-fixture/runs/run_fixture1');
  assert.equal(detail.status, 200);
  assert.equal(detail.json.id, 'run_fixture1');
  assert.equal(detail.json.modules.length, 1);

  const missing = await httpRequest('/api/engagements/dash-fixture/runs/run_missing');
  assert.equal(missing.status, 404);
});

test('evidence can be fetched by id and unknown ids are 404', async () => {
  const res = await httpRequest(`/api/engagements/dash-fixture/evidence/${knownEvidenceId}`);
  assert.equal(res.status, 200);
  assert.equal(res.json.id, knownEvidenceId);
  assert.equal(res.json.response.bodyPreview, 'fixture body');
  assert.ok(!res.text.includes('super-secret'), 'authorization header must stay redacted');

  const missing = await httpRequest('/api/engagements/dash-fixture/evidence/ev_missing');
  assert.equal(missing.status, 404);
  assert.equal(missing.json.code, 'not_found');

  const list = await httpRequest('/api/engagements/dash-fixture/evidence');
  assert.equal(list.status, 200);
  assert.equal(list.json.evidence.length, 1);
});

test('PATCH finding rejects missing and wrong tokens with 401', async () => {
  const missing = await patchFinding(findingCritical.id, { status: 'fixed' });
  assert.equal(missing.status, 401);
  assert.equal(missing.json.code, 'auth.invalid_token');
  assert.equal(missing.json.error.length > 0, true);

  const wrong = await patchFinding(findingCritical.id, { status: 'fixed' }, 'not-the-token');
  assert.equal(wrong.status, 401);
  assert.equal(wrong.json.code, 'auth.invalid_token');

  const still = await httpRequest(`/api/engagements/dash-fixture/findings/${findingCritical.id}`);
  assert.equal(still.json.status, 'open', 'rejected requests must not change state');
});

test('PATCH finding with the token updates and persists status', async () => {
  const res = await patchFinding(findingCritical.id, { status: 'fixed', note: 'patched in test' }, TOKEN);
  assert.equal(res.status, 200);
  assert.equal(res.json.finding.id, findingCritical.id);
  assert.equal(res.json.finding.status, 'fixed');
  assert.equal(res.json.finding.history.at(-1).note, 'patched in test');
  assert.equal(res.json.finding.history.at(-1).actor, 'operator');

  const viaApi = await httpRequest(`/api/engagements/dash-fixture/findings/${findingCritical.id}`);
  assert.equal(viaApi.json.status, 'fixed');

  const reopened = await EngagementStore.open('dash-fixture', { engagementsRoot, logger: silentLogger() });
  try {
    const persisted = reopened.getFinding(findingCritical.id);
    assert.ok(persisted, 'finding exists after reopening the store');
    assert.equal(persisted.status, 'fixed', 'status is flushed to disk, not just in memory');
  } finally {
    await reopened.close();
  }
});

test('PATCH finding validates status and finding ids', async () => {
  const invalid = await patchFinding(findingMedium.id, { status: 'exploited' }, TOKEN);
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json.code, 'finding.invalid_status');

  const empty = await patchFinding(findingMedium.id, {}, TOKEN);
  assert.equal(empty.status, 400);

  const missing = await patchFinding('fnd_missing', { status: 'fixed' }, TOKEN);
  assert.equal(missing.status, 404);
  assert.equal(missing.json.code, 'not_found');

  const note = await patchFinding(findingMedium.id, { note: 'operator note only' }, TOKEN);
  assert.equal(note.status, 200);
  assert.equal(note.json.finding.status, 'open');
  assert.equal(note.json.finding.history.at(-1).event, 'annotated');
});

test('report endpoint serves json/md/html or a clean 501', async () => {
  const json = await httpRequest('/api/engagements/dash-fixture/report?format=json');
  assert.ok([200, 501].includes(json.status), `unexpected report status ${json.status}`);
  if (json.status === 200) {
    assert.match(json.headers['content-type'], /application\/json/);
  } else {
    assert.equal(json.json.error, 'report module not available');
    assert.equal(json.json.code, 'report.unavailable');
  }

  const invalid = await httpRequest('/api/engagements/dash-fixture/report?format=pdf');
  assert.equal(invalid.status, 400);
  assert.equal(invalid.json.code, 'report.invalid_format');
});

test('unknown API endpoints return JSON 404s', async () => {
  const res = await httpRequest('/api/nope');
  assert.equal(res.status, 404);
  assert.equal(res.json.code, 'not_found');
  assert.ok(res.json.error);

  const deep = await httpRequest('/api/engagements/dash-fixture/nope');
  assert.equal(deep.status, 404);
  assert.equal(deep.json.code, 'not_found');

  const wrongMethod = await httpRequest('/api/engagements/dash-fixture/findings', { method: 'POST' });
  assert.equal(wrongMethod.status, 405);
  assert.equal(wrongMethod.json.code, 'method.not_allowed');
  assert.match(wrongMethod.headers.allow, /GET/);
});

test('unknown engagement ids return 404', async () => {
  const res = await httpRequest('/api/engagements/does-not-exist');
  assert.equal(res.status, 404);
  assert.equal(res.json.code, 'not_found');

  const bad = await httpRequest('/api/engagements/..%2F..%2Fpackage.json');
  assert.equal(bad.status, 404);
});

test('static UI is served with correct content types', async () => {
  const index = await httpRequest('/');
  assert.equal(index.status, 200);
  assert.match(index.headers['content-type'], /text\/html/);
  assert.match(index.text, /VANTAGE/);

  const app = await httpRequest('/app.js');
  assert.equal(app.status, 200);
  assert.match(app.headers['content-type'], /javascript/);
  assert.match(app.text, /EventSource|VANTAGE/);

  const css = await httpRequest('/styles.css');
  assert.equal(css.status, 200);
  assert.match(css.headers['content-type'], /text\/css/);

  const head = await httpRequest('/', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(head.text, '');
});

test('path traversal never escapes ui/', async () => {
  const attempts = [
    '/../package.json',
    '/%2e%2e/package.json',
    '/%2e%2e%2f%2e%2e%2fpackage.json',
    '/..%2fserver%2findex.js',
    '/ui/../../package.json'
  ];
  for (const attempt of attempts) {
    const res = await httpRequest(attempt);
    assert.ok([400, 404].includes(res.status), `${attempt} returned ${res.status}`);
    assert.ok(!res.text.includes('mvt-timeline-viewer'), `${attempt} leaked a file outside ui/`);
    assert.ok(!res.text.includes('createApiHandler'), `${attempt} leaked server source`);
  }
});

test('SSE sends hello, reports event-stream headers and forwards bus events', async () => {
  const stream = openEventStream('/api/events?engagementId=dash-fixture');
  try {
    await withTimeout(stream.first, 5000, 'SSE first frame');
    assert.equal(stream.state.status, 200);
    assert.match(stream.state.headers['content-type'], /text\/event-stream/);
    assert.equal(stream.state.headers['cache-control'], 'no-store, no-transform');
    assert.equal(stream.state.headers['x-accel-buffering'], 'no');
    assert.match(stream.state.data, /^retry: \d+/);
    assert.match(stream.state.data, /event: hello/);
    assert.match(stream.state.data, /"startedAt"/);
    assert.match(stream.state.data, /"engagementId":"dash-fixture"/);

    bus.publish({ type: 'run:start', engagementId: 'dash-fixture', runId: 'run_sse' });
    await withTimeout(stream.eventSeen, 5000, 'SSE forwarded event');
    assert.match(stream.state.data, /event: run:start/);
    assert.match(stream.state.data, /run_sse/);
    assert.equal(bus.status().engine.running, true);
    bus.publish({ type: 'run:done', engagementId: 'dash-fixture', runId: 'run_sse' });
    assert.equal(bus.status().engine.running, false);
  } finally {
    stream.close();
  }
});

test('a data dir containing no engagements behaves like an empty dashboard', async () => {
  const emptyRoot = await tempDir('vantage-empty-test-');
  const spare = createServer({ dataDir: path.join(emptyRoot, 'data'), token: 'spare-token', logger: silentLogger() });
  try {
    const url = await spare.start(0);
    const sparePort = Number(new URL(url).port);
    const body = await new Promise((resolve, reject) => {
      http
        .get({ hostname: '127.0.0.1', port: sparePort, path: '/api/engagements' }, (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') }));
        })
        .on('error', reject);
    });
    assert.equal(body.status, 200);
    assert.deepEqual(JSON.parse(body.text), []);
  } finally {
    await spare.close();
    await fs.rm(emptyRoot, { recursive: true, force: true });
  }
});
