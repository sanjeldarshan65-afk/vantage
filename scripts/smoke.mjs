/**
 * Import/instantiation smoke test: every core module must load and agree with its neighbours.
 * Run with `node vantage/scripts/smoke.mjs`.
 */
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { promises as fs } from 'node:fs';

const modules = [
  '../src/core/paths.js',
  '../src/core/util.js',
  '../src/core/errors.js',
  '../src/core/log.js',
  '../src/core/defaults.js',
  '../src/core/scope.js',
  '../src/core/rate.js',
  '../src/core/audit.js',
  '../src/core/findings.js',
  '../src/core/evidence.js',
  '../src/core/http.js',
  '../src/core/dns.js',
  '../src/core/guard.js',
  '../src/core/store.js',
  '../src/core/registry.js',
  '../src/core/webprobe.js',
  '../src/core/engine.js'
];

for (const specifier of modules) {
  const mod = await import(specifier);
  if (!mod || Object.keys(mod).length === 0) throw new Error(`${specifier} exported nothing`);
  console.log(`ok  ${specifier} (${Object.keys(mod).length} exports)`);
}

const { Scope } = await import('../src/core/scope.js');
const { EngagementStore } = await import('../src/core/store.js');
const { ScopeGuard } = await import('../src/core/guard.js');
const { Engine } = await import('../src/core/engine.js');
const { ModuleRegistry } = await import('../src/core/registry.js');
const { silentLogger } = await import('../src/core/log.js');
const { newId } = await import('../src/core/util.js');

const server = http.createServer((req, res) => {
  if (req.url === '/.env') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('SECRET_KEY=abc\n');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/html', server: 'smoke' });
  res.end('<html><body>ok</body></html>');
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vantage-smoke-'));
const document = {
  engagement: {
    id: 'smoke',
    name: 'Smoke',
    client: 'Internal',
    authorizedBy: 'test',
    authorizationRef: 'UNIT-TEST',
    startsAt: '2020-01-01T00:00:00.000Z',
    mode: 'safe'
  },
  scope: {
    targets: [`http://127.0.0.1:${port}`],
    limits: { requestsPerSecond: 50, perHostRequestsPerSecond: 50, concurrency: 4, maxRequests: 100, timeoutMs: 3000 }
  }
};

const store = await EngagementStore.create(document, { engagementsRoot: path.join(tmpRoot, 'engagements'), logger: silentLogger() });
const logger = silentLogger();
const guard = new ScopeGuard({ engagement: store.engagement, scope: store.scope, logger, audit: store.audit, evidence: store.evidence });

const verdict = await guard.authorize({ url: `http://127.0.0.1:${port}/` });
if (!verdict.allowed) throw new Error(`expected in-scope, got: ${verdict.reason}`);
const outside = await guard.authorize({ url: 'http://127.0.0.1:9/' });
if (outside.allowed) throw new Error('port 9 should have been refused');

const response = await guard.fetch(`http://127.0.0.1:${port}/.env`);
if (response.status !== 200) throw new Error('fetch failed');
if (!response.evidence?.id) throw new Error('fetch produced no evidence');
const stored = await store.evidence.get(response.evidence.id);
if (!stored) throw new Error('evidence not retrievable');

const registry = new ModuleRegistry().register({
  id: 'smoke.demo',
  phase: 'recon',
  title: 'Smoke module',
  async run(ctx) {
    const res = await ctx.guard.fetch(ctx.target.url ?? `http://127.0.0.1:${port}/`);
    await ctx.addFinding({
      check: 'smoke.demo.finding',
      title: 'Smoke finding',
      severity: 'low',
      target: res.url,
      evidence: [res.evidence.id],
      description: 'created by smoke test',
      remediation: 'none',
      observed: [{ key: 'status', value: String(res.status) }]
    });
    await ctx.addAsset({ type: 'endpoint', value: res.url, state: 'tested' });
  }
});

const engine = new Engine({ store, guard, logger, registry });
const result = await engine.run({ phases: ['recon'], moduleTimeoutMs: 10000 });
const report = await store.snapshot();
console.log(`run ${result.run.id} status=${result.run.status} findings=${report.summary.total} assets=${report.assets.length} evidence=${report.evidenceCount}`);
if (report.summary.total !== 1) throw new Error('expected exactly one finding');
if (report.evidenceCount < 1) throw new Error('expected evidence');

await store.close();
server.close();
await fs.rm(tmpRoot, { recursive: true, force: true });
console.log(`\nSMOKE OK (${newId('tmp')})`);
