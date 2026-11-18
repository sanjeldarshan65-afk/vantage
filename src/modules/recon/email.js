/**
 * recon.email — email authentication posture (SPF, DMARC, DKIM selector discovery).
 *
 * Read-only: TXT lookups against the engagement's own DNS resolver via `ctx.dns`. The module never
 * sends mail, never validates credentials and never contacts a mailbox.
 *
 * Findings are phrased for a client report: every issue carries a concrete remediation and a
 * severity that reflects realistic impact, not just spec compliance.
 */
import { isIP } from 'node:net';
import { normalizeHost, truncate } from '../../core/util.js';

/** Public suffixes where the registrable domain is three labels (`example.co.uk`). */
const SECOND_LEVEL_SUFFIXES = new Set(['uk', 'au', 'nz', 'jp', 'br', 'za', 'in', 'kr', 'sg', 'hk', 'mx', 'ar', 'tr']);
/** Second-level labels that signal a public suffix (used with the TLD list above). */
const SECOND_LEVEL_LABELS = new Set(['co', 'com', 'org', 'net', 'ac', 'gov', 'edu']);

/** Common DKIM selectors, most frequent first. */
export const DKIM_SELECTORS = Object.freeze([
  'default',
  'google',
  'selector1',
  'selector2',
  'k1',
  'mail',
  's1',
  's2',
  'dkim',
  'mx'
]);

/** Mechanisms that consume one of the RFC 7208 ten-DNS-lookup allowance. */
const SPF_LOOKUP_MECHANISM = /^[+\-~?]?(include|a|mx|ptr|exists)(?::|$)/i;
const SPF_ALL = /^([+\-~?]?)all$/i;
const SPF_VERSION = /^v=spf1(?:\s|$)/i;

/**
 * Heuristic registrable domain (apex) for a hostname.
 *
 * Uses the last two labels, except for a curated list of public suffixes where three labels are
 * required (`foo.co.uk` → `foo.co.uk`, `mail.foo.co.uk` → `foo.co.uk`). This is intentionally a
 * conservative heuristic, not a full Public Suffix List: callers can override it with
 * `ctx.options.module.apex` when a target sits on an unlisted suffix.
 *
 * @param {string} host hostname or IP literal
 * @returns {string} lowercased apex, or the input (normalized) when it cannot be derived
 */
export function deriveApex(host) {
  const value = normalizeHost(host);
  if (!value || isIP(value)) return value;
  const labels = value.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const last = labels.at(-1);
  const secondLast = labels.at(-2);
  if (SECOND_LEVEL_SUFFIXES.has(last) && SECOND_LEVEL_LABELS.has(secondLast)) {
    return labels.slice(-3).join('.');
  }
  return labels.slice(-2).join('.');
}

/**
 * Extract the SPF version record from a set of apex TXT records.
 * @param {string[]} records flattened TXT strings (`ctx.dns.resolveTxt().records`)
 * @returns {string|null} the first `v=spf1` record, or null
 */
export function findSpfRecord(records) {
  if (!Array.isArray(records)) return null;
  for (const record of records) {
    const text = String(record ?? '').trim();
    if (SPF_VERSION.test(text)) return text;
  }
  return null;
}

/**
 * Analyse an SPF policy.
 *
 * @param {string[]|null|undefined} records TXT records for the apex; null/undefined means the
 *   lookup failed and no conclusion can be drawn
 * @returns {{present: boolean, record: string|null, lookups: number, allQualifier: string|null,
 *   issues: Array<{code: string, severity: string, title: string, detail: string}>}}
 */
export function analyzeSpf(records) {
  const empty = { present: false, record: null, lookups: 0, allQualifier: null, issues: [] };
  if (records == null) return empty;
  if (!Array.isArray(records)) return empty;
  const record = findSpfRecord(records);
  if (!record) {
    return {
      ...empty,
      issues: [
        {
          code: 'spf-missing',
          severity: 'medium',
          title: 'SPF not published',
          detail: 'No TXT record starting with "v=spf1" was found at the domain apex.'
        }
      ]
    };
  }

  const terms = record.split(/\s+/).filter(Boolean).slice(1);
  let lookups = 0;
  let allQualifier = null;
  for (const rawTerm of terms) {
    const term = rawTerm.replace(/^\(/, '').replace(/\)$/, '');
    if (SPF_ALL.test(term)) {
      const [, qualifier = '+'] = term.match(SPF_ALL) ?? [];
      allQualifier = qualifier || '+';
      continue;
    }
    if (SPF_LOOKUP_MECHANISM.test(term)) lookups += 1;
    if (/^redirect=/i.test(term)) lookups += 1;
  }

  const issues = [];
  if (allQualifier === '+') {
    issues.push({
      code: 'spf-all-pass',
      severity: 'high',
      title: 'SPF uses the "+all" mechanism',
      detail: 'The policy ends in "+all", authorizing every host on the internet to send mail as this domain.'
    });
  } else if (allQualifier === '~') {
    issues.push({
      code: 'spf-softfail',
      severity: 'low',
      title: 'SPF uses the "~all" soft-fail mechanism',
      detail: 'The policy ends in "~all": unauthorized mail is only marked as suspicious, not rejected.'
    });
  }
  if (lookups > 10) {
    issues.push({
      code: 'spf-too-many-lookups',
      severity: 'low',
      title: 'SPF exceeds the 10 DNS-lookup limit',
      detail: `The policy uses ${lookups} DNS-lookup mechanisms; RFC 7208 permits 10, so compliant receivers may return a permanent error and defeat the policy.`
    });
  }
  return {
    present: true,
    record,
    lookups: Math.min(lookups, 99),
    allQualifier,
    issues
  };
}

/**
 * Parse a DMARC record's tag/value pairs.
 * @param {string} record
 * @returns {Record<string,string>} lowercased tag names
 */
export function parseDmarcTags(record) {
  const tags = {};
  if (typeof record !== 'string') return tags;
  for (const part of record.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const index = trimmed.indexOf('=');
    if (index <= 0) continue;
    const key = trimmed.slice(0, index).trim().toLowerCase();
    const value = trimmed.slice(index + 1).trim();
    if (key) tags[key] = value;
  }
  return tags;
}

/**
 * Analyse a DMARC policy record (the TXT record at `_dmarc.<apex>`).
 *
 * @param {string[]|null|undefined} records TXT records for `_dmarc.<apex>`
 * @returns {{present: boolean, record: string|null, policy: string|null, tags: Record<string,string>,
 *   issues: Array<{code: string, severity: string, title: string, detail: string}>}}
 */
export function analyzeDmarc(records) {
  const empty = { present: false, record: null, policy: null, tags: {}, issues: [] };
  if (records == null || !Array.isArray(records)) return empty;
  const record = records.map((entry) => String(entry ?? '').trim()).find((entry) => /^v=dmarc1(?:\s*;|$)/i.test(entry));
  if (!record) {
    return {
      ...empty,
      issues: [
        {
          code: 'dmarc-missing',
          severity: 'medium',
          title: 'DMARC not published',
          detail: 'No DMARC record ("v=DMARC1") was found at _dmarc.<domain>.'
        }
      ]
    };
  }
  const tags = parseDmarcTags(record);
  const policy = (tags.p ?? '').toLowerCase() || null;
  const issues = [];
  if (policy === 'none') {
    issues.push({
      code: 'dmarc-policy-none',
      severity: 'low',
      title: 'DMARC is in monitoring mode (p=none)',
      detail: 'The policy requests no enforcement, so spoofed mail is delivered even though reports are collected.'
    });
  } else if (policy === 'quarantine' || policy === 'reject') {
    issues.push({
      code: 'dmarc-enforcing',
      severity: 'info',
      title: `DMARC policy enforces p=${policy}`,
      detail: `DMARC is published and enforcing with p=${policy}; keep rua reporting monitored and re-validate after mail-flow changes.`
    });
  } else {
    issues.push({
      code: 'dmarc-invalid-policy',
      severity: 'medium',
      title: 'DMARC record has a missing or invalid p= policy',
      detail: `The record does not declare a usable p= tag (found: ${policy ?? 'none'}). Receivers will not enforce the intended policy.`
    });
  }
  return { present: true, record, policy, tags, issues };
}

/** Per-code report narrative used when an issue becomes a finding. */
const NARRATIVES = Object.freeze({
  'spf-missing': {
    description:
      'The domain publishes no SPF record. Receivers have no authorized-sender list to evaluate, so mail claiming to come from this domain is treated on reputation alone.',
    impact:
      'Attackers can spoof the domain in phishing and business-email-compromise campaigns; receivers, partners and customers cannot reliably distinguish forged mail from legitimate mail.',
    remediation:
      'Publish a single SPF TXT record at the domain apex, for example "v=spf1 include:_spf.example.net -all", listing only the sending services actually used. Keep the record under the ten-lookup limit, use "-all" once the inventory is complete, and review it whenever a mail provider changes.',
    references: [
      'https://www.rfc-editor.org/rfc/rfc7208',
      'https://owasp.org/www-community/attacks/Email_Header_Injection'
    ],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'spf-all-pass': {
    description:
      'The SPF record ends with the "+all" mechanism, which authorizes every IP address on the internet to send mail for this domain.',
    impact:
      'The policy provides no protection at all: any sender, including an attacker on a cloud host, passes SPF. Combined with a permissive DMARC policy this enables convincing spoofing of the domain.',
    remediation:
      'Replace "+all" with "-all" (hard fail) after confirming the complete list of legitimate senders. If the inventory is not yet complete, use "~all" as a temporary step and finish the inventory promptly.',
    references: ['https://www.rfc-editor.org/rfc/rfc7208#section-5.1'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'spf-softfail': {
    description:
      'The SPF record terminates in "~all" (soft fail), which asks receivers to mark unauthorized mail as suspicious rather than reject it.',
    impact:
      'Spoofed mail that fails SPF may still be delivered to inboxes or spam folders depending on the receiver, weakening the domain\'s anti-spoofing posture.',
    remediation:
      'Once all legitimate senders are inventoried, change "~all" to "-all" and monitor DMARC aggregate reports to catch senders missed by the inventory.',
    references: ['https://www.rfc-editor.org/rfc/rfc7208#section-2.6.6'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'spf-too-many-lookups': {
    description:
      'The SPF policy exceeds the RFC 7208 allowance of ten DNS-lookup mechanisms. Compliant receivers return a permanent error (permerror) for any mail that reaches the eleventh lookup.',
    impact:
      'Legitimate mail can fail SPF unpredictably and be quarantined or rejected, while the policy appears configured; the failure is hard to diagnose from the sender side.',
    remediation:
      'Flatten the SPF record: replace nested "include:" chains with the providers\' concrete ip4/ip6 ranges (or a managed SPF flattening service), remove unused mechanisms, and re-test the lookup count with an SPF checker after every change.',
    references: ['https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'dmarc-missing': {
    description:
      'No DMARC record is published for the domain. Receivers cannot tell the domain owner how to handle mail that fails SPF/DKIM alignment, and no aggregate reporting is defined.',
    impact:
      'Without DMARC, spoofed mail benefits from weak SPF/DKIM results; the organization also receives no visibility into who is sending as its domain.',
    remediation:
      'Publish a TXT record at _dmarc.<domain> starting with "v=DMARC1; p=none; rua=mailto:dmarc-reports@<domain>", collect aggregate reports for several weeks, then move to "p=quarantine" and finally "p=reject" with an appropriate "pct" ramp.',
    references: ['https://www.rfc-editor.org/rfc/rfc7489', 'https://dmarc.org/overview/'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'dmarc-policy-none': {
    description:
      'The DMARC record exists but requests no action (p=none). Reports are collected, but receivers still deliver mail that fails authentication.',
    impact:
      'Spoofed messages continue to reach recipients while the domain appears to have DMARC configured, which can create a false sense of protection.',
    remediation:
      'Validate the sending inventory from the aggregate reports, then publish an enforcement policy, for example "v=DMARC1; p=quarantine; pct=25; rua=...", raising pct to 100 and moving to p=reject as confidence grows.',
    references: ['https://www.rfc-editor.org/rfc/rfc7489#section-6.2'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'dmarc-enforcing': {
    description:
      'The DMARC record is published and enforcing (p=quarantine or p=reject). This is the recommended end state.',
    impact: 'No direct impact; this is a positive control observation useful for the report and retest baseline.',
    remediation:
      'No immediate action. Keep the rua address monitored, keep DKIM keys rotated, and re-check DMARC alignment after changes to mail infrastructure or third-party senders.',
    references: ['https://www.rfc-editor.org/rfc/rfc7489'],
    cwe: [],
    owasp: ['A07:2021']
  },
  'dmarc-invalid-policy': {
    description:
      'The DMARC record is present but does not declare a valid p= policy tag. Receivers fall back to a default of no enforcement.',
    impact:
      'The domain appears to have DMARC while spoofed mail is still delivered; report aggregation may also be missing or misdirected.',
    remediation:
      'Repair the record: publish exactly one DMARC record with a p= tag of none, quarantine or reject, valid rua/ruf URIs, and a single semicolon-separated tag list. Remove duplicate or malformed records.',
    references: ['https://www.rfc-editor.org/rfc/rfc7489#section-6.3'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  },
  'dkim-no-common-selector': {
    description:
      'No DKIM public key was found at any commonly used selector for this domain. DKIM signing may use a custom selector, so this is a lead rather than proof of a missing control.',
    impact:
      'Without usable DKIM, DMARC alignment relies on SPF alone; forwarded mail is more likely to fail authentication and be quarantined.',
    remediation:
      'Confirm which selector the mail platform signs with and publish the corresponding public key as TXT at <selector>._domainkey.<domain>. Use 2048-bit RSA keys or Ed25519, rotate keys periodically, and publish key records before enabling signing.',
    references: ['https://www.rfc-editor.org/rfc/rfc6376', 'https://www.rfc-editor.org/rfc/rfc8301'],
    cwe: ['CWE-290'],
    owasp: ['A07:2021']
  }
});

/** Finding texts for an analyze issue, copied so callers cannot mutate the frozen table. */
function narrativeFor(code) {
  return NARRATIVES[code] ?? {
    description: 'An email authentication configuration issue was observed.',
    impact: 'Weakened anti-spoofing guarantees for the domain.',
    remediation: 'Review the SPF, DKIM and DMARC configuration with the mail provider.',
    references: [],
    cwe: [],
    owasp: ['A07:2021']
  };
}

/** Remaining request budget, or Infinity when the host context has no limiter (tests). */
function budgetRemaining(ctx) {
  const remaining = ctx?.guard?.limiter?.budget?.remaining;
  return Number.isFinite(remaining) ? remaining : Infinity;
}

/** Evidence id of a DNS answer, when the guard stored one. */
function evidenceOf(result) {
  return result?.evidenceId ?? null;
}

/**
 * Run a TXT lookup without ever throwing: missing records, timeouts and scope refusals all degrade
 * to `{ records: [], error }` so the collector can decide whether a finding is justified.
 */
async function safeResolveTxt(ctx, host) {
  if (!ctx.dns || typeof ctx.dns.resolveTxt !== 'function') {
    return { host, records: [], error: 'dns-unavailable', evidenceId: null };
  }
  try {
    const result = await ctx.dns.resolveTxt(host);
    return { host, records: Array.isArray(result?.records) ? result.records : [], error: result?.error ?? null, evidenceId: result?.evidenceId ?? null };
  } catch (error) {
    ctx.logger?.debug?.(`TXT lookup for ${host} failed: ${error?.message ?? error}`);
    return { host, records: [], error: error?.code ?? 'lookup-failed', evidenceId: null };
  }
}

/**
 * Emit one analyze issue as a finding.
 * @returns {Promise<object|null>}
 */
async function emitIssue(ctx, { code, issue, target, evidence, extraObserved = [] }) {
  if (!issue) return null;
  const narrative = narrativeFor(code);
  const absence = code === 'spf-missing' || code === 'dmarc-missing' || code === 'dkim-no-common-selector';
  return ctx.addFinding({
    check: `recon.email.${code}`,
    title: issue.title,
    severity: issue.severity,
    confidence: code === 'dkim-no-common-selector' ? 'possible' : absence ? 'likely' : 'confirmed',
    target,
    evidence: evidence.filter(Boolean),
    observed: [{ key: 'detail', value: truncate(issue.detail, 400) }, ...extraObserved],
    description: narrative.description,
    impact: narrative.impact,
    remediation: narrative.remediation,
    references: narrative.references,
    cwe: narrative.cwe,
    owasp: narrative.owasp
  });
}

export default {
  id: 'recon.email',
  phase: 'recon',
  title: 'Email authentication (SPF, DMARC, DKIM)',
  description:
    'Checks the domain apex for SPF and DMARC policy records and probes common DKIM selectors. Reports spoofing exposure with concrete mail-flow fixes.',
  defaults: { apex: null, dkimSelectors: [...DKIM_SELECTORS], maxSelectors: 10 },
  async run(ctx) {
    const host = normalizeHost(ctx.target?.host ?? '');
    if (!host) {
      ctx.logger?.debug?.('recon.email: no host in target, skipping');
      return { notes: ['email: target has no hostname; skipped'] };
    }
    if (isIP(host)) {
      await ctx.addAsset({ type: 'ip', value: host });
      return { notes: ['email: target is an IP literal; no domain email policy applies'] };
    }

    const override = normalizeHost(ctx.options?.module?.apex ?? '');
    const apex = override || deriveApex(host);
    const domainAsset = await ctx.addAsset({ type: 'domain', value: apex, state: 'tested' });
    if (host !== apex) {
      await ctx.addAsset({ type: 'subdomain', value: host, parent: domainAsset, state: 'tested' });
    }

    const notes = [];
    const evidence = [];

    // SPF at the apex.
    const spfLookup = await safeResolveTxt(ctx, apex);
    evidence.push(evidenceOf(spfLookup));
    if (spfLookup.error && spfLookup.records.length === 0) {
      notes.push(`SPF lookup for ${apex} failed (${spfLookup.error}); no SPF finding emitted`);
    } else {
      const spf = analyzeSpf(spfLookup.records);
      for (const issue of spf.issues) {
        await emitIssue(ctx, {
          code: issue.code,
          issue,
          target: apex,
          evidence: [spfLookup.evidenceId],
          extraObserved: spf.record ? [{ key: 'spf', value: truncate(spf.record, 500) }, { key: 'dns-lookups', value: String(spf.lookups) }] : []
        });
      }
      if (spf.present) ctx.logger?.info?.(`SPF for ${apex}: ${spf.issues.length} issue(s), ${spf.lookups} DNS lookups`);
    }

    // DMARC under _dmarc.<apex>.
    const dmarcHost = `_dmarc.${apex}`;
    if (budgetRemaining(ctx) >= 5 && !ctx.signal?.aborted) {
      const dmarcLookup = await safeResolveTxt(ctx, dmarcHost);
      evidence.push(evidenceOf(dmarcLookup));
      if (dmarcLookup.error && dmarcLookup.records.length === 0) {
        notes.push(`DMARC lookup for ${dmarcHost} failed (${dmarcLookup.error}); no DMARC finding emitted`);
      } else {
        const dmarc = analyzeDmarc(dmarcLookup.records);
        for (const issue of dmarc.issues) {
          await emitIssue(ctx, {
            code: issue.code,
            issue,
            target: apex,
            evidence: [dmarcLookup.evidenceId],
            extraObserved: dmarc.record ? [{ key: 'dmarc', value: truncate(dmarc.record, 500) }] : []
          });
        }
        if (dmarc.present) ctx.logger?.info?.(`DMARC for ${apex}: policy=${dmarc.policy ?? 'invalid'}`);
      }
    }

    // DKIM: try common selectors, stop at the first record found or when the budget runs low.
    const selectors = (Array.isArray(ctx.options?.module?.dkimSelectors) ? ctx.options.module.dkimSelectors : DKIM_SELECTORS)
      .map((selector) => normalizeHost(selector))
      .filter(Boolean)
      .slice(0, Number(ctx.options?.module?.maxSelectors) || DKIM_SELECTORS.length);
    let foundSelector = null;
    const tried = [];
    for (const selector of selectors) {
      if (ctx.signal?.aborted) break;
      if (budgetRemaining(ctx) < 20) break;
      const dkimHost = `${selector}._domainkey.${apex}`;
      const lookup = await safeResolveTxt(ctx, dkimHost);
      tried.push(selector);
      if (lookup.records.length > 0) {
        foundSelector = selector;
        evidence.push(evidenceOf(lookup));
        break;
      }
      if (lookup.error && lookup.error !== 'ENODATA' && lookup.error !== 'ENOTFOUND') {
        // Resolver error rather than an authoritative empty answer: stop probing instead of
        // turning a resolver outage into a "no DKIM" claim.
        notes.push(`DKIM lookup for ${dkimHost} failed (${lookup.error}); selector probing stopped`);
        break;
      }
    }
    if (foundSelector) {
      ctx.logger?.info?.(`DKIM selector found for ${apex}: ${foundSelector}`);
      await ctx.addAsset({
        type: 'domain',
        value: apex,
        attributes: { dkimSelector: foundSelector },
        state: 'tested'
      });
    } else if (tried.length >= selectors.length && !ctx.signal?.aborted) {
      const narrative = narrativeFor('dkim-no-common-selector');
      await ctx.addFinding({
        check: 'recon.email.dkim-no-common-selector',
        title: 'No DKIM key found on common selectors',
        severity: 'low',
        confidence: 'possible',
        target: apex,
        evidence: evidence.filter(Boolean),
        observed: [{ key: 'selectors-tried', value: tried.join(', ') }],
        description: narrative.description,
        impact: narrative.impact,
        remediation: narrative.remediation,
        references: narrative.references,
        cwe: narrative.cwe,
        owasp: narrative.owasp
      });
    }

    ctx.logger?.debug?.(`email checks finished for ${apex} (${tried.length} DKIM selectors tried)`);
    return { notes };
  }
};
