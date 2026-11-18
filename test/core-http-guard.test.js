import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import zlib from 'node:zlib';
import { ScopeError } from '../src/core/errors.js';
import { createTestStore, createTestGuard, startServer, engagementDoc } from './_helpers.js';
import { EngagementStore } from '../src/core/store.js';
import { ScopeGuard } from '../src/core/guard.js';
import { tcpProbe, tlsProbe } from '../src/core/tcp.js';

/** Start a store whose scope covers exactly the given servers' origins. */
async function harness(servers) {
  const targets = servers.map((entry) => entry.url);
  const { store, root, engagementsRoot } = await createTestStore({ targets });
  const guard = createTestGuard(store);
  return { store, root, engagementsRoot, guard };
}

test('fetch returns status, headers, body and evidence', async () => {
  const srv = await startServer((req, res) => {
    res.writeHead(201, { 'content-type': 'text/plain', 'x-test': 'yes' });
    res.end('hello world');
  });
  const { store, root, guard } = await harness([srv]);
  try {
    const res = await guard.fetch(`${srv.url}/thing`);
    assert.equal(res.status, 201);
    assert.equal(res.text, 'hello world');
    assert.equal(res.header('X-Test'), 'yes');
    assert.ok(res.evidence?.id);
    assert.ok(res.evidence.sha256);
    const stored = await store.evidence.get(res.evidence.id);
    assert.ok(stored);
    assert.equal(stored.response.status, 201);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('redirects inside scope are followed and recorded', async () => {
  const srv = await startServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { location: '/final' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('arrived');
  });
  const { store, root, guard } = await harness([srv]);
  try {
    const res = await guard.fetch(`${srv.url}/start`);
    assert.equal(res.status, 200);
    assert.equal(res.text, 'arrived');
    assert.equal(res.redirects.length, 1);
    assert.match(res.redirects[0].location, /\/final$/);
    assert.match(res.url, /\/final$/);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('a redirect leaving scope is stopped, not followed', async () => {
  const outside = await startServer((req, res) => {
    res.writeHead(200);
    res.end('should never be reached');
  });
  const inside = await startServer((req, res) => {
    res.writeHead(302, { location: outside.url });
    res.end();
  });
  const { store, root, guard } = await harness([inside]);
  try {
    const res = await guard.fetch(`${inside.url}/`);
    assert.equal(res.status, 302, 'the in-scope response is returned');
    assert.ok(res.redirectsBlocked);
    assert.match(res.redirectsBlocked.reason, /not covered by any in-scope rule|excluded/);
  } finally {
    await outside.close();
    await inside.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('an out-of-scope host is refused and the refusal is audited', async () => {
  const outside = await startServer((req, res) => res.end('nope'));
  const inside = await startServer((req, res) => res.end('ok'));
  const { store, root, guard } = await harness([inside]);
  try {
    await assert.rejects(() => guard.fetch(`${outside.url}/`), ScopeError);
    await store.audit.flush();
    const rows = await store.audit.read();
    const denied = rows.filter((row) => row.allowed === false);
    assert.ok(denied.length >= 1, 'denial must be in the audit trail');
    assert.ok(denied.some((row) => /deny/.test(row.action)));
  } finally {
    await outside.close();
    await inside.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('evidence redacts credentials but keeps cookie attributes', async () => {
  const srv = await startServer((req, res) => {
    res.writeHead(200, {
      'content-type': 'text/plain',
      'set-cookie': ['session=supersecret; Secure; HttpOnly; SameSite=Strict']
    });
    res.end('ok');
  });
  const { store, root, guard } = await harness([srv]);
  try {
    await guard.fetch(`${srv.url}/`, { headers: { authorization: 'Bearer topsecret', cookie: 'other=abc' } });
    await store.evidence.flush();
    const rows = await store.evidence.list();
    assert.equal(rows.length, 1);
    const text = JSON.stringify(rows[0]);
    assert.ok(!text.includes('topsecret'));
    assert.ok(!text.includes('supersecret'));
    assert.ok(!text.includes('abc'));
    assert.ok(text.includes('HttpOnly'), 'cookie flags remain readable in evidence');
    assert.equal(rows[0].kind, 'http');
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('large bodies are truncated at maxBytes', async () => {
  const srv = await startServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('x'.repeat(10000));
  });
  const { store, root, guard } = await harness([srv]);
  try {
    const res = await guard.fetch(`${srv.url}/`, { maxBytes: 100 });
    assert.equal(res.response.truncated, true);
    assert.ok(res.response.bytes <= 100);
    assert.ok(res.response.receivedBytes >= 100);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('gzip and brotli bodies are decoded', async () => {
  const srv = await startServer((req, res) => {
    if (req.url === '/gzip') {
      res.writeHead(200, { 'content-encoding': 'gzip', 'content-type': 'text/plain' });
      res.end(zlib.gzipSync('gzipped body'));
      return;
    }
    res.writeHead(200, { 'content-encoding': 'br', 'content-type': 'text/plain' });
    res.end(zlib.brotliCompressSync('brotli body'));
  });
  const { store, root, guard } = await harness([srv]);
  try {
    assert.equal((await guard.fetch(`${srv.url}/gzip`)).text, 'gzipped body');
    assert.equal((await guard.fetch(`${srv.url}/br`)).text, 'brotli body');
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('head() falls back to GET when HEAD breaks the connection', async () => {
  const srv = await startServer((req, res) => {
    if (req.method === 'HEAD') {
      req.socket.destroy();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('fallback');
  });
  const { store, root, guard } = await harness([srv]);
  try {
    const res = await guard.head(`${srv.url}/`);
    assert.equal(res.status, 200);
    assert.equal(res.text, 'fallback');
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('429 is retried when allowed and surfaced when retries are off', async () => {
  let hits = 0;
  const srv = await startServer((req, res) => {
    hits += 1;
    if (hits === 1) {
      res.writeHead(429, { 'retry-after': '0' });
      res.end('slow down');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok now');
  });
  const { store, root, guard } = await harness([srv]);
  try {
    const retried = await guard.fetch(`${srv.url}/`);
    assert.equal(retried.status, 200);
    assert.equal(hits, 2);

    hits = 0;
    const noRetry = await guard.fetch(`${srv.url}/`, { retryOnThrottle: false });
    assert.equal(noRetry.status, 429);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('method gate only allows read-only verbs (plus POST with an explicit body)', async () => {
  const srv = await startServer((req, res) => res.end('ok'));
  const { store, root, guard } = await harness([srv]);
  try {
    await assert.rejects(() => guard.fetch(`${srv.url}/`, { method: 'PUT' }), /not permitted/);
    await assert.rejects(() => guard.fetch(`${srv.url}/`, { method: 'DELETE' }), /not permitted/);
    const trace = await guard.fetch(`${srv.url}/`, { method: 'TRACE' });
    assert.ok(trace.status >= 200);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('the request budget stops runaway modules', async () => {
  const srv = await startServer((req, res) => res.end('ok'));
  const { store, root, guard } = await harness([srv]);
  try {
    guard.limiter.budget.max = 2;
    guard.limiter.budget.used = 0;
    await guard.fetch(`${srv.url}/1`);
    await guard.fetch(`${srv.url}/2`);
    await assert.rejects(() => guard.fetch(`${srv.url}/3`), /budget exhausted/);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('tcpProbe reports open and closed ports without throwing', async () => {
  const srv = await startServer((req, res) => res.end('ok'));
  const dead = await startServer((req, res) => res.end('ok'));
  const { store, root, guard } = await harness([srv, dead]);
  await dead.close(); // in scope, but nothing listens any more
  try {
    const open = await guard.tcpProbe('127.0.0.1', srv.port);
    assert.equal(open.open, true);
    assert.ok(open.evidenceId, 'a banner-less open port still records audit');

    const closed = await guard.tcpProbe('127.0.0.1', dead.port, { timeoutMs: 600 });
    assert.equal(closed.open, false);
    assert.ok(closed.error);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('tlsProbe against a plain HTTP port fails gracefully and records evidence', async () => {
  const srv = await startServer((req, res) => res.end('ok'));
  const { store, root, guard } = await harness([srv]);
  try {
    const result = await guard.tlsProbe('127.0.0.1', srv.port, { timeoutMs: 1200 });
    assert.equal(result.open, false);
    assert.ok(result.error);
    assert.ok(result.evidenceId);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});

test('raw tcp/tls helpers bound their own timeouts', async () => {
  const tcp = await tcpProbe('127.0.0.1', 1, { timeoutMs: 400 });
  assert.equal(tcp.open, false);
  const tlsResult = await tlsProbe('127.0.0.1', 1, { timeoutMs: 400 });
  assert.equal(tlsResult.open, false);
  assert.ok(tlsResult.elapsedMs >= 0);
});

test('authorization window outside the engagement blocks the guard', async () => {
  const srv = await startServer((req, res) => res.end('ok'));
  const doc = engagementDoc({ targets: [srv.url], endsAt: '2020-02-01T00:00:00.000Z' });
  const { store, root } = await createTestStore({ targets: [srv.url], endsAt: doc.engagement.endsAt });
  const guard = createTestGuard(store);
  try {
    await assert.rejects(() => guard.fetch(`${srv.url}/`), ScopeError);
  } finally {
    await srv.close();
    await store.close();
    await import('node:fs/promises').then((fs) => fs.rm(root, { recursive: true, force: true }));
  }
});
