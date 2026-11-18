import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { promises as fs } from 'node:fs';
import {
  newId,
  sha256,
  shortHash,
  nowIso,
  normalizeHost,
  parseHostPort,
  defaultPort,
  ipToBigInt,
  parseCidr,
  cidrContains,
  isPrivateAddress,
  redactHeaders,
  redactUrl,
  truncate,
  formatBytes,
  percent,
  severityRank,
  SEVERITY_ORDER,
  clamp,
  writeJsonAtomic,
  readJson,
  appendJsonl,
  readJsonl,
  countLines,
  ensureDir
} from '../src/core/util.js';
import { tempDir } from './_helpers.js';

test('newId is prefixed, unique and hex', () => {
  const ids = new Set();
  for (let i = 0; i < 200; i += 1) ids.add(newId('fnd'));
  assert.equal(ids.size, 200);
  for (const id of ids) assert.match(id, /^fnd_[0-9a-f]{12}$/);
});

test('sha256 and shortHash are stable', () => {
  assert.equal(sha256('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(shortHash('abc', 8), 'ba7816bf');
  assert.equal(shortHash('abc'), shortHash('abc'));
  assert.notEqual(shortHash('abc'), shortHash('abd'));
});

test('normalizeHost strips case, trailing dots and brackets', () => {
  assert.equal(normalizeHost('Example.COM.'), 'example.com');
  assert.equal(normalizeHost('[::1]'), '::1');
  assert.equal(normalizeHost('  '), '');
  assert.equal(normalizeHost(null), '');
});

test('parseHostPort handles bare hosts, ports, URLs and IPv6', () => {
  assert.deepEqual(parseHostPort('example.com'), { host: 'example.com', port: null });
  assert.equal(parseHostPort('example.com:8443').port, 8443);
  const url = parseHostPort('https://example.com/path');
  assert.equal(url.host, 'example.com');
  assert.equal(url.port, 443);
  assert.equal(url.scheme, 'https');
  assert.equal(parseHostPort('http://example.com:8080/').port, 8080);
  const v6 = parseHostPort('[2001:db8::1]:443');
  assert.equal(v6.host, '2001:db8::1');
  assert.equal(v6.port, 443);
  assert.equal(defaultPort('https'), 443);
  assert.equal(defaultPort('http'), 80);
  assert.equal(defaultPort('ftp'), null);
});

test('CIDR math works for IPv4 and IPv6', () => {
  assert.equal(ipToBigInt('0.0.0.0'), 0n);
  assert.equal(ipToBigInt('127.0.0.1'), 2130706433n);
  assert.equal(ipToBigInt('not-an-ip'), null);
  const net = parseCidr('192.168.1.0/24');
  assert.equal(net.bits, 24);
  assert.equal(net.family, 4);
  assert.ok(cidrContains(net, '192.168.1.55'));
  assert.ok(!cidrContains(net, '192.168.2.1'));
  assert.ok(parseCidr('nonsense') === null);
  assert.ok(parseCidr('10.0.0.0/33') === null);
  const v6 = parseCidr('2001:db8::/32');
  assert.equal(v6.family, 6);
  assert.ok(cidrContains(v6, '2001:db8:1234::1'));
  assert.ok(!cidrContains(v6, '2001:db9::1'));
});

test('isPrivateAddress classifies ranges', () => {
  assert.equal(isPrivateAddress('127.0.0.1'), true);
  assert.equal(isPrivateAddress('10.1.2.3'), true);
  assert.equal(isPrivateAddress('172.16.5.5'), true);
  assert.equal(isPrivateAddress('192.168.0.1'), true);
  assert.equal(isPrivateAddress('169.254.1.1'), true);
  assert.equal(isPrivateAddress('8.8.8.8'), false);
  assert.equal(isPrivateAddress('::1'), true);
  assert.equal(isPrivateAddress('nope'), false);
});

test('redaction removes credentials but keeps structure', () => {
  const headers = redactHeaders({ Authorization: 'Bearer secret', Cookie: 'session=abc', 'X-Trace': '123' });
  assert.equal(headers.Authorization, '<redacted>');
  assert.equal(headers.Cookie, '<redacted>');
  assert.equal(headers['X-Trace'], '123');

  const redacted = redactUrl('https://user:pass@example.com/a?token=abc&page=2&api_key=zzz');
  assert.ok(redacted.includes('token=%3Credacted%3E') || redacted.includes('token=<redacted>'));
  assert.ok(redacted.includes('page=2'));
  assert.ok(!redacted.includes('abc'));
  assert.ok(!redacted.includes('pass'));
});

test('small formatting helpers behave', () => {
  assert.equal(truncate('abcdef', 4), 'abcd…');
  assert.equal(truncate(null, 4), '');
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(2048), '2.0 KiB');
  assert.equal(percent(1, 4), 25);
  assert.equal(percent(1, 0), 0);
  assert.deepEqual(SEVERITY_ORDER, ['critical', 'high', 'medium', 'low', 'info']);
  assert.equal(severityRank('critical'), 0);
  assert.equal(severityRank('info'), 4);
  assert.equal(severityRank('bogus'), 5);
  assert.equal(clamp(12, 0, 10), 10);
  assert.equal(clamp(-1, 0, 10), 0);
  assert.match(nowIso(), /^\d{4}-\d{2}-\d{2}T/);
});

test('json/jsonl helpers round-trip and tolerate a torn line', async () => {
  const dir = await tempDir();
  try {
    const file = path.join(dir, 'nested', 'data.json');
    await writeJsonAtomic(file, { a: 1 });
    assert.deepEqual(await readJson(file), { a: 1 });
    assert.deepEqual(await readJson(path.join(dir, 'missing.json'), { fallback: true }), { fallback: true });

    await ensureDir(dir);
    const jsonl = path.join(dir, 'rows.jsonl');
    await appendJsonl(jsonl, { n: 1 });
    await appendJsonl(jsonl, { n: 2 });
    await fs.appendFile(jsonl, '{"n":3'); // simulated crash mid-write
    const rows = await readJsonl(jsonl);
    assert.deepEqual(rows, [{ n: 1 }, { n: 2 }]);
    assert.equal(await readJsonl(path.join(dir, 'none.jsonl')).then((r) => r.length), 0);
    assert.equal(await countLines(jsonl), 3, 'raw line count includes the torn line');
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
});
