/**
 * web.securitytxt — RFC 9116 security.txt, the standard way for researchers to report issues.
 *
 * Pure helper `analyzeSecurityTxt(text, now)` is exported for tests.
 */

const RFC = 'https://www.rfc-editor.org/rfc/rfc9116';

/**
 * Parse and grade a security.txt body.
 * @param {string} text
 * @param {number} [now]
 * @returns {{fields: Record<string, string[]>, problems: {check: string, severity: string, title: string, detail: string}[]}}
 */
export function analyzeSecurityTxt(text, now = Date.now()) {
  const fields = {};
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line.trim());
    if (m && !line.trim().startsWith('#')) (fields[m[1].toLowerCase()] ??= []).push(m[2].trim());
  }
  const problems = [];
  if (!fields.contact?.length) {
    problems.push({ check: 'web.securitytxt.no-contact', severity: 'low', title: 'security.txt has no Contact field',
      detail: 'Contact is required by RFC 9116; without it researchers have no way to report a problem.' });
  }
  const expires = fields.expires?.[0];
  if (!expires) {
    problems.push({ check: 'web.securitytxt.no-expires', severity: 'info', title: 'security.txt has no Expires field',
      detail: 'Expires is required by RFC 9116 so readers know the file is maintained.' });
  } else if (Date.parse(expires) < now) {
    problems.push({ check: 'web.securitytxt.expired', severity: 'low', title: 'security.txt has expired',
      detail: `The Expires date (${expires}) is in the past, so readers should treat the contact details as stale.` });
  }
  return { fields, problems };
}

export default {
  id: 'web.securitytxt',
  phase: 'web',
  title: 'security.txt',
  description: 'Checks for an RFC 9116 security.txt with Contact and a future Expires date.',
  defaults: {},
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) return { notes: ['no web target answered'] };
    const url = ctx.helpers.joinUrl(probe.url, '/.well-known/security.txt');
    let res;
    try {
      res = await ctx.guard.fetch(url, { signal: ctx.signal });
    } catch (error) {
      if (error?.code === 'scope.denied') throw error;
      ctx.logger.debug?.(`security.txt fetch failed: ${error.message}`);
      return { notes: ['security.txt could not be fetched'] };
    }
    const type = String(res.header('content-type') ?? '');
    const looksLikeFile = res.status === 200 && /text\/plain/i.test(type) && /^\s*(contact|expires|#)/im.test(res.text);
    const base = { confidence: 'confirmed', target: url, evidence: [res.evidence.id], references: [RFC], cwe: [], owasp: [] };
    if (!looksLikeFile) {
      await ctx.addFinding({ ...base, check: 'web.securitytxt.missing', severity: 'info',
        title: 'No security.txt file', observed: [{ key: 'status', value: String(res.status) }],
        description: 'There is no /.well-known/security.txt telling researchers how to report a vulnerability.',
        impact: 'People who find a problem may not report it, or may report it publicly.',
        remediation: 'Publish /.well-known/security.txt with at least Contact and Expires fields (securitytxt.org can generate one).' });
      return;
    }
    const { fields, problems } = analyzeSecurityTxt(res.text);
    for (const p of problems) {
      await ctx.addFinding({ ...base, check: p.check, severity: p.severity, title: p.title,
        observed: Object.entries(fields).slice(0, 6).map(([key, v]) => ({ key, value: v.join(', ') })),
        description: p.detail, impact: 'Researchers may not be able to reach the right person in time.',
        remediation: 'Update /.well-known/security.txt so it has a working Contact and an Expires date within the next year.' });
    }
    return { notes: [`security.txt present with ${Object.keys(fields).length} field(s)`] };
  }
};
