import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeCertificate, analyzeLegacyProtocols } from '../src/modules/web/tls.js';
import { CANDIDATES, matchExposure, envKeyNames, isDirectoryListing } from '../src/modules/web/exposure.js';
import { analyzeSecurityTxt } from '../src/modules/web/securitytxt.js';
import { classifyPort } from '../src/modules/recon/ports.js';
import { redactSecrets } from '../src/core/evidence.js';

const NOW = Date.parse('2026-11-18T00:00:00Z');
const cert = (over = {}) => ({ subject: { CN: 'a.example' }, issuer: { O: 'CA' }, validTo: 'Dec 31 00:00:00 2027 GMT', selfSigned: false, hostnameMatch: true, keyType: 'RSA', keyBits: 2048, ...over });
const checks = (list) => list.map((f) => f.check);

test('tls: healthy certificate produces no findings', () => {
  assert.deepEqual(analyzeCertificate(cert(), { now: NOW, target: 't' }), []);
  assert.deepEqual(analyzeCertificate(null, { now: NOW, target: 't' }), []);
});

test('tls: expired, expiring, self-signed, mismatch, weak key, untrusted', () => {
  assert.deepEqual(checks(analyzeCertificate(cert({ validTo: 'Nov 1 00:00:00 2026 GMT' }), { now: NOW, target: 't' })), ['web.tls.cert-expired']);
  const soon = analyzeCertificate(cert({ validTo: 'Nov 21 00:00:00 2026 GMT' }), { now: NOW, target: 't' });
  assert.equal(soon[0].check, 'web.tls.cert-expiring');
  assert.equal(soon[0].severity, 'medium');
  assert.deepEqual(checks(analyzeCertificate(cert({ selfSigned: true }), { now: NOW, target: 't', authorized: false })), ['web.tls.self-signed']);
  assert.deepEqual(checks(analyzeCertificate(cert({ hostnameMatch: false }), { now: NOW, target: 't' })), ['web.tls.hostname-mismatch']);
  assert.deepEqual(checks(analyzeCertificate(cert({ keyBits: 1024 }), { now: NOW, target: 't' })), ['web.tls.weak-key']);
  assert.deepEqual(checks(analyzeCertificate(cert(), { now: NOW, target: 't', authorized: false, authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })), ['web.tls.untrusted']);
});

test('tls: legacy protocols only reported when a handshake completed', () => {
  assert.deepEqual(analyzeLegacyProtocols([{ version: 'TLS 1.0', open: false }], { target: 't' }), []);
  const [f] = analyzeLegacyProtocols([{ version: 'TLS 1.0', open: true, evidenceId: 'ev_1' }, { version: 'TLS 1.1', open: false }], { target: 't' });
  assert.equal(f.title, 'Server accepts TLS 1.0');
  assert.deepEqual(f.evidence, ['ev_1']);
});

test('exposure: content signatures, not status codes, decide', () => {
  const git = CANDIDATES.find((c) => c.path === '/.git/HEAD');
  const env = CANDIDATES.find((c) => c.path === '/.env');
  assert.ok(matchExposure(git, 200, 'ref: refs/heads/main\n'));
  assert.ok(!matchExposure(git, 200, '<!doctype html><h1>Home</h1>'), 'soft 404 page is not a leak');
  assert.ok(!matchExposure(git, 404, 'ref: refs/heads/main'));
  assert.ok(matchExposure(env, 200, 'APP_KEY=abc\nDB_HOST=x'));
  assert.ok(!matchExposure(env, 200, '<html><body>A=1</body></html>'));
  const ds = CANDIDATES.find((c) => c.path === '/.DS_Store');
  assert.ok(matchExposure(ds, 200, '', Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31])));
  assert.deepEqual(envKeyNames('A_KEY=1\nexport BB=2\n# CC=3'), ['A_KEY', 'BB']);
  assert.ok(isDirectoryListing('<html><title>Index of /</title>'));
  assert.ok(!isDirectoryListing('<title>Home</title>'));
});

test('evidence redaction keeps key names and drops secret values', () => {
  const out = redactSecrets('APP_NAME=demo\nDB_PASSWORD=hunter2\nexport AWS_SECRET_ACCESS_KEY=abc\napi_key: xyz\n-----BEGIN RSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----');
  assert.match(out, /APP_NAME=demo/);
  assert.match(out, /DB_PASSWORD=<redacted>/);
  assert.match(out, /AWS_SECRET_ACCESS_KEY=<redacted>/);
  assert.match(out, /api_key: <redacted>/);
  assert.ok(!/hunter2|xyz|MII/.test(out));
});

test('security.txt: valid, missing contact, expired', () => {
  assert.deepEqual(analyzeSecurityTxt('Contact: mailto:a@b.example\nExpires: 2027-06-01T00:00:00Z', NOW).problems, []);
  assert.deepEqual(analyzeSecurityTxt('Expires: 2027-06-01T00:00:00Z', NOW).problems.map((p) => p.check), ['web.securitytxt.no-contact']);
  assert.deepEqual(analyzeSecurityTxt('Contact: x\nExpires: 2020-01-01T00:00:00Z', NOW).problems.map((p) => p.check), ['web.securitytxt.expired']);
  assert.deepEqual(analyzeSecurityTxt('# Contact: x', NOW).problems.map((p) => p.check), ['web.securitytxt.no-contact', 'web.securitytxt.no-expires']);
});

test('ports: risky services are classified, others are not', () => {
  assert.equal(classifyPort(6379).service, 'Redis');
  assert.equal(classifyPort(2375).severity, 'critical');
  assert.equal(classifyPort(443), null);
});

test('headers: meta CSP counts for fetch directives but not for framing', async () => {
  const { analyzeHeaders, metaCspFromHtml } = await import('../src/modules/web/headers.js');
  const html = { 'content-type': 'text/html' };
  const meta = metaCspFromHtml(`<head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head>`);
  assert.equal(meta, "default-src 'self'");
  assert.equal(metaCspFromHtml('<meta name="viewport" content="x">'), null);

  const withMeta = analyzeHeaders(html, { url: 'https://a.example/', metaCsp: meta }).findings.map((f) => f.check);
  assert.ok(!withMeta.includes('web.headers.missing-csp'), 'meta CSP is not "missing"');
  assert.ok(withMeta.includes('web.headers.csp-meta-only'));
  assert.ok(withMeta.includes('web.headers.missing-frame-protection'), 'meta CSP cannot stop framing');

  const none = analyzeHeaders(html, { url: 'https://a.example/' }).findings.map((f) => f.check);
  assert.ok(none.includes('web.headers.missing-csp'));
  assert.ok(none.includes('web.headers.missing-frame-protection'), 'no CSP and no XFO is clickjackable (was a false negative)');

  const protectedPage = analyzeHeaders({ ...html, 'content-security-policy': "default-src 'self'; frame-ancestors 'none'" }, { url: 'https://a.example/' }).findings.map((f) => f.check);
  assert.ok(!protectedPage.includes('web.headers.missing-frame-protection'));
});

test('headers: meta referrer policy counts, unsafe values still flagged', async () => {
  const { analyzeHeaders, metaReferrerFromHtml } = await import('../src/modules/web/headers.js');
  const html = { 'content-type': 'text/html' };
  const meta = metaReferrerFromHtml('<meta name="referrer" content="strict-origin-when-cross-origin">');
  assert.equal(meta, 'strict-origin-when-cross-origin');
  const ok = analyzeHeaders(html, { url: 'https://a.example/', metaReferrer: meta }).findings.map((f) => f.check);
  assert.ok(!ok.includes('web.headers.missing-referrer-policy'));
  const bad = analyzeHeaders(html, { url: 'https://a.example/', metaReferrer: 'unsafe-url' }).findings.map((f) => f.check);
  assert.ok(bad.includes('web.headers.unsafe-referrer-policy'));
});

test('headers: SRI only flags cross-origin scripts and stylesheets without integrity', async () => {
  const { analyzeSubresourceIntegrity } = await import('../src/modules/web/headers.js');
  const page = 'https://a.example/';
  const html = [
    '<script src="/app.js"></script>',
    '<script src="https://cdn.example/lib.js" integrity="sha384-x" crossorigin="anonymous"></script>',
    '<script src="https://cdn.example/bad.js"></script>',
    '<link rel="stylesheet" href="https://fonts.example/f.css">',
    '<link rel="icon" href="https://cdn.example/i.png">'
  ].join('\n');
  const f = analyzeSubresourceIntegrity(html, { url: page });
  assert.equal(f.check, 'web.headers.missing-sri');
  assert.match(f.observed[0].value, /bad\.js/);
  assert.match(f.observed[0].value, /f\.css/);
  assert.doesNotMatch(f.observed[0].value, /lib\.js|app\.js|i\.png/);
  assert.equal(analyzeSubresourceIntegrity('<script src="/x.js"></script>', { url: page }), null);
});
