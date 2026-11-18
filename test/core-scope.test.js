import test from 'node:test';
import assert from 'node:assert/strict';
import {
  Scope,
  parseScopeEntry,
  normalizeEngagement,
  withinWindow,
  createEngagementTemplate,
  urlScopeInput,
  MODES
} from '../src/core/scope.js';
import { ConfigError } from '../src/core/errors.js';

test('parseScopeEntry understands every supported form', () => {
  assert.equal(parseScopeEntry('app.example.com').type, 'host');
  assert.equal(parseScopeEntry('*.example.com').type, 'wildcard');
  assert.equal(parseScopeEntry('10.0.0.5').type, 'ip');
  assert.equal(parseScopeEntry('10.0.0.0/24').type, 'cidr');
  const url = parseScopeEntry('https://app.example.com');
  assert.equal(url.type, 'url');
  assert.equal(url.port, 443);
  assert.equal(parseScopeEntry('http://app.example.com:8080').port, 8080);
});

test('parseScopeEntry rejects dangerous or malformed entries', () => {
  assert.throws(() => parseScopeEntry(''), ConfigError);
  assert.throws(() => parseScopeEntry('*.com'), ConfigError, 'single-label wildcard is too broad');
  assert.throws(() => parseScopeEntry('*'), ConfigError);
  assert.throws(() => parseScopeEntry('0.0.0.0/0'), ConfigError, 'default route is too broad');
  assert.throws(() => parseScopeEntry('::/0'), ConfigError);
  assert.throws(() => parseScopeEntry('-bad-.com'), ConfigError);
  assert.throws(() => parseScopeEntry('ftp://example.com'), ConfigError);
  assert.throws(() => parseScopeEntry('https://user:pass@example.com'), ConfigError);
});

test('a scope without targets is refused', () => {
  assert.throws(() => new Scope({ targets: [] }), ConfigError);
  assert.throws(() => new Scope({}), ConfigError);
});

test('host, wildcard and apex matching', () => {
  const scope = new Scope({ targets: ['app.example.com', '*.example.org', 'example.net'] });
  assert.equal(scope.matchHost('app.example.com').allowed, true);
  assert.equal(scope.matchHost('APP.example.com').allowed, true);
  assert.equal(scope.matchHost('other.example.com').allowed, false);
  assert.equal(scope.matchHost('a.example.org').allowed, true);
  assert.equal(scope.matchHost('a.b.example.org').allowed, true);
  assert.equal(scope.matchHost('example.org').allowed, false, 'wildcards do not cover the apex');
  assert.equal(scope.matchHost('example.net').allowed, true);
  assert.equal(scope.matchHost('evil-example.net').allowed, false);
});

test('URL scope entries constrain scheme and port', () => {
  const scope = new Scope({ targets: ['https://secure.example.com'] });
  assert.equal(scope.matchHost('secure.example.com', { scheme: 'https', port: 443 }).allowed, true);
  assert.equal(scope.matchHost('secure.example.com', { scheme: 'http', port: 80 }).allowed, false);
  assert.equal(scope.matchHost('secure.example.com', { scheme: 'https', port: 8443 }).allowed, false);
  // DNS-style checks (no scheme/port) still allow the host.
  assert.equal(scope.matchHost('secure.example.com').allowed, true);
});

test('IP and CIDR entries match literals and resolved hostnames', () => {
  const scope = new Scope({ targets: ['10.0.0.0/24', '203.0.113.9'] });
  assert.equal(scope.matchHost('10.0.0.4').allowed, true);
  assert.equal(scope.matchHost('10.0.1.4').allowed, false);
  assert.equal(scope.matchHost('203.0.113.9').allowed, true);
  assert.equal(scope.matchHost('203.0.113.10').allowed, false);
  assert.equal(scope.matchHost('app.internal', { port: 80, resolvedIps: ['10.0.0.7'] }).allowed, true);
  assert.equal(scope.matchHost('app.internal', { port: 80, resolvedIps: ['10.0.9.7'] }).allowed, false);
});

test('exclusions always win, including by CIDR', () => {
  const scope = new Scope({ targets: ['*.example.com', '10.0.0.0/8'], exclude: ['admin.example.com', '10.9.0.0/16'] });
  assert.equal(scope.matchHost('www.example.com').allowed, true);
  assert.equal(scope.matchHost('admin.example.com').allowed, false);
  assert.match(scope.matchHost('admin.example.com').reason, /excluded/);
  assert.equal(scope.matchHost('10.9.1.1').allowed, false);
  assert.equal(scope.matchHost('internal.example.com', { resolvedIps: ['10.9.1.1'] }).allowed, false, 'excluded by resolved IP');
});

test('port gates reject before the host is even considered', () => {
  const scope = new Scope({ targets: ['app.example.com'], ports: { include: [80, 443], exclude: [443] } });
  assert.equal(scope.matchHost('app.example.com', { port: 80 }).allowed, true);
  assert.equal(scope.matchHost('app.example.com', { port: 443 }).allowed, false);
  assert.equal(scope.matchHost('app.example.com', { port: 22 }).allowed, false);
  assert.match(scope.matchHost('app.example.com', { port: 22 }).reason, /not in the allowed port list/);
  assert.deepEqual(scope.allowedPort(80), { allowed: true, reason: 'port 80 is allowed' });
});

test('normalizeEngagement validates, defaults and clamps', () => {
  const { engagement, scope } = normalizeEngagement({
    engagement: {
      id: 'acme-lab',
      name: 'ACME Lab',
      authorizationRef: 'SOW-1',
      startsAt: '2026-01-01T00:00:00Z',
      endsAt: '2026-02-01T00:00:00Z',
      mode: 'full'
    },
    scope: {
      targets: ['https://acme.example'],
      limits: { requestsPerSecond: 999, concurrency: 99, maxRequests: 10, timeoutMs: 1 }
    }
  });
  assert.equal(engagement.id, 'acme-lab');
  assert.equal(engagement.mode, 'full');
  assert.equal(scope.mode, 'full');
  assert.equal(scope.limits.requestsPerSecond, 50, 'clamped to the hard ceiling');
  assert.equal(scope.limits.concurrency, 16);
  assert.equal(scope.limits.timeoutMs, 500);
  assert.equal(scope.limits.maxRequests, 10);
  assert.equal(MODES.includes(engagement.mode), true);
});

test('normalizeEngagement refuses missing authorization and bad ids', () => {
  assert.throws(() => normalizeEngagement({ engagement: { id: 'Bad Id' }, scope: { targets: ['x.example.com'] } }), ConfigError);
  assert.throws(
    () => normalizeEngagement({ engagement: { id: 'ok', authorizationRef: '  ' }, scope: { targets: ['x.example.com'] } }),
    /authorizationRef/
  );
  assert.throws(() => normalizeEngagement(null), ConfigError);
  assert.throws(
    () => normalizeEngagement({ engagement: { id: 'ok', authorizationRef: 'x', startsAt: 'not-a-date' }, scope: { targets: ['x.example.com'] } }),
    /startsAt/
  );
  assert.throws(
    () =>
      normalizeEngagement({
        engagement: { id: 'ok', authorizationRef: 'x', startsAt: '2026-02-01', endsAt: '2026-01-01' },
        scope: { targets: ['x.example.com'] }
      }),
    /before/
  );
});

test('authorization window is enforced', () => {
  const engagement = { startsAt: '2026-01-01T00:00:00.000Z', endsAt: '2026-02-01T00:00:00.000Z' };
  assert.equal(withinWindow(engagement, new Date('2026-01-15T00:00:00Z')).allowed, true);
  assert.equal(withinWindow(engagement, new Date('2025-12-01T00:00:00Z')).allowed, false);
  assert.equal(withinWindow(engagement, new Date('2026-03-01T00:00:00Z')).allowed, false);
  const openEnded = { startsAt: null, endsAt: null };
  assert.equal(withinWindow(openEnded).allowed, true);
});

test('templates describe a coherent scope', () => {
  const doc = createEngagementTemplate({ id: 'demo', name: 'Demo', targets: ['http://127.0.0.1:8080'], client: 'Internal' });
  assert.equal(doc.engagement.id, 'demo');
  assert.deepEqual(doc.scope.targets, ['http://127.0.0.1:8080']);
  assert.ok(doc.scope.limits.maxRequests > 0);
  const { scope } = normalizeEngagement(doc);
  assert.equal(scope.matchHost('127.0.0.1', { port: 8080, scheme: 'http' }).allowed, true);
  assert.equal(scope.matchHost('127.0.0.1', { port: 8081, scheme: 'http' }).allowed, false);
  assert.throws(() => createEngagementTemplate({ id: 'x', targets: [] }), ConfigError);
});

test('urlScopeInput and describe expose the guard input', () => {
  const input = urlScopeInput('https://app.example.com:8443/x');
  assert.equal(input.host, 'app.example.com');
  assert.equal(input.port, 8443);
  assert.equal(input.scheme, 'https');
  const scope = new Scope({ targets: ['app.example.com'] });
  const described = scope.describe();
  assert.deepEqual(described.targets, ['app.example.com']);
  assert.equal(described.mode, 'safe');
  assert.deepEqual(scope.toJSON().targets, ['app.example.com']);
});
