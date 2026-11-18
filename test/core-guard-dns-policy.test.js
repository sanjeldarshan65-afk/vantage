import { test } from 'node:test';
import assert from 'node:assert/strict';
import { promises as fs } from 'node:fs';
import { dnsPolicyOwner } from '../src/core/guard.js';
import { createTestStore, createTestGuard } from './_helpers.js';

test('dnsPolicyOwner strips underscore labels only', () => {
  assert.equal(dnsPolicyOwner('_dmarc.acme.example'), 'acme.example');
  assert.equal(dnsPolicyOwner('s1._domainkey.acme.example'), 'acme.example');
  assert.equal(dnsPolicyOwner('_mta-sts.mail.acme.example'), 'mail.acme.example');
  assert.equal(dnsPolicyOwner('www.acme.example'), null);
  assert.equal(dnsPolicyOwner('_dmarc.com'), null, 'never widen to a bare TLD');
});

test('DNS policy records of an in-scope domain are allowed for DNS only', async () => {
  const { store, root } = await createTestStore({ targets: ['https://acme.example'] });
  const guard = createTestGuard(store);
  try {
    const dns = await guard.authorize({ host: '_dmarc.acme.example', kind: 'dns' });
    assert.equal(dns.allowed, true);
    assert.match(dns.reason, /DNS policy record/);
    const dkim = await guard.authorize({ host: 'default._domainkey.acme.example', kind: 'dns' });
    assert.equal(dkim.allowed, true);
  } finally {
    await store.close();
    await fs.rm(root, { recursive: true, force: true });
  }
});
