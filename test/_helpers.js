import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import { EngagementStore } from '../src/core/store.js';
import { ScopeGuard } from '../src/core/guard.js';
import { silentLogger } from '../src/core/log.js';

/** Fresh temp directory, removed by the caller. */
export async function tempDir(prefix = 'vantage-test-') {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

/** A minimal valid engagement document for tests. */
export function engagementDoc({
  id = 'test-engagement',
  targets = ['http://127.0.0.1:8080'],
  mode = 'safe',
  limits = {},
  options = {},
  endsAt = null
} = {}) {
  return {
    engagement: {
      id,
      name: 'Test Engagement',
      client: 'Internal',
      authorizedBy: 'Test Operator',
      authorizationRef: 'UNIT-TEST-AUTHORIZATION',
      startsAt: '2020-01-01T00:00:00.000Z',
      endsAt,
      mode,
      notes: 'Created by the test harness.'
    },
    scope: {
      targets,
      exclude: [],
      ports: { include: [], exclude: [] },
      limits: {
        requestsPerSecond: 50,
        perHostRequestsPerSecond: 50,
        concurrency: 4,
        maxRequests: 200,
        timeoutMs: 3000,
        maxResponseBytes: 65536,
        maxEvidenceBytes: 2048,
        ...limits
      },
      allowThirdParty: false
    },
    options
  };
}

/** Create a temp engagements root plus an open store. */
export async function createTestStore(opts = {}) {
  const root = await tempDir();
  const engagementsRoot = path.join(root, 'engagements');
  const store = await EngagementStore.create(engagementDoc(opts), { engagementsRoot, logger: silentLogger() });
  return { root, engagementsRoot, store, cleanup: () => cleanupStore(store, root) };
}

/** Close and delete. */
export async function cleanupStore(store, root) {
  await store.close();
  await fs.rm(root, { recursive: true, force: true });
}

/** Guard wired to the store's audit/evidence streams (as the engine does). */
export function createTestGuard(store) {
  return new ScopeGuard({
    engagement: store.engagement,
    scope: store.scope,
    logger: silentLogger(),
    audit: store.audit,
    evidence: store.evidence
  });
}

/** Start a local HTTP server on a random loopback port. */
export async function startServer(handler) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    server,
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

/** Read a JSON body from Node's `http` response. */
export function readBody(res) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    res.on('data', (chunk) => chunks.push(chunk));
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    res.on('error', reject);
  });
}

/** Wait until `predicate()` is truthy or the timeout expires. */
export async function waitFor(predicate, { timeoutMs = 2000, intervalMs = 20 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return false;
}
