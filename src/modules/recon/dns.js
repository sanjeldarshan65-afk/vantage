/**
 * recon.dns — DNS inventory and CNAME/subdomain-takeover triage.
 *
 * Read-only DNS via `ctx.dns` (the scope-checked, audited choke point). No zone transfer, no
 * resolver brute force: a fixed set of record types for the run target, plus a short, bounded
 * CNAME walk so a dangling chain can be reported as a lead for manual validation.
 */
import { isIP } from 'node:net';
import { normalizeHost, truncate } from '../../core/util.js';
import { deriveApex } from './email.js';

/**
 * Provider suffixes with a well-known subdomain-takeover surface.
 *
 * Matching one of these is a lead, not proof: the record is only exploitable when the backing
 * resource has been released and can be claimed by somebody else.
 */
export const TAKEOVER_SUFFIXES = Object.freeze([
  's3.amazonaws.com',
  '*.s3.amazonaws.com',
  'github.io',
  '*.github.io',
  'herokuapp.com',
  '*.herokuapp.com',
  'azurewebsites.net',
  '*.azurewebsites.net',
  'cloudfront.net',
  'netlify.app',
  'vercel.app',
  'fastly.net',
  'digitaloceanspaces.com',
  'wpengine.com',
  'myshopify.com',
  'elasticbeanstalk.com',
  'trafficmanager.net',
  'readme.io',
  'surge.sh'
]);

/** Record types collected for every target, in collection order. */
const RECORD_TYPES = Object.freeze(['CNAME', 'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']);

/**
 * Normalize a DNS name for comparison: lowercase, strip a trailing dot and surrounding spaces.
 * @param {string} value
 * @returns {string}
 */
export function normalizeDnsName(value) {
  return normalizeHost(value ?? '');
}

/**
 * Match a CNAME target against the curated takeover-prone provider list.
 * @param {string} host CNAME target (or any hostname)
 * @returns {string|null} the matched suffix rule, or null
 */
export function matchTakeoverSuffix(host) {
  const target = normalizeDnsName(host);
  if (!target) return null;
  for (const suffix of TAKEOVER_SUFFIXES) {
    const base = suffix.startsWith('*.') ? suffix.slice(2) : suffix;
    if (target === base || target.endsWith(`.${base}`)) return suffix;
  }
  return null;
}

/**
 * Summarize an observed CNAME chain and flag takeover candidates.
 *
 * @param {string} host the name the chain starts at
 * @param {string[]} cnameTargets ordered CNAME targets observed (one per hop, host excluded)
 * @returns {{host: string, hops: string[], chain: string[], dangling: Array<{target: string, suffix: string}>,
 *   isDangling: boolean}}
 */
export function analyzeCnameChain(host, cnameTargets) {
  const root = normalizeDnsName(host);
  const hops = (Array.isArray(cnameTargets) ? cnameTargets : []).map(normalizeDnsName).filter(Boolean);
  const dangling = [];
  const seen = new Set();
  for (const target of hops) {
    if (seen.has(target)) continue;
    seen.add(target);
    const suffix = matchTakeoverSuffix(target);
    if (suffix) dangling.push({ target, suffix });
  }
  return { host: root, hops, chain: [root, ...hops], dangling, isDangling: dangling.length > 0 };
}

/**
 * Count records per type for an inventory observation.
 * @param {Record<string, string[]|object[]|object|null>} records map of rrtype → answer
 * @returns {{counts: Record<string, number>, total: number, types: string[]}}
 */
export function summarizeDnsRecords(records) {
  const counts = {};
  let total = 0;
  for (const type of RECORD_TYPES) {
    const answer = records?.[type];
    const count = Array.isArray(answer) ? answer.length : answer ? 1 : 0;
    counts[type] = count;
    total += count;
  }
  return { counts, total, types: RECORD_TYPES.filter((type) => counts[type] > 0) };
}

/** Remaining request budget, or Infinity when there is no limiter (tests). */
function budgetRemaining(ctx) {
  const remaining = ctx?.guard?.limiter?.budget?.remaining;
  return Number.isFinite(remaining) ? remaining : Infinity;
}

/** Normalize the answer shapes `ctx.dns` can return for the record types we collect. */
function answerValues(rrtype, result) {
  const records = Array.isArray(result?.records) ? result.records : [];
  switch (rrtype) {
    case 'CNAME':
    case 'NS':
      return records.map((entry) => normalizeDnsName(typeof entry === 'string' ? entry : entry?.value)).filter(Boolean);
    case 'A':
    case 'AAAA':
      return records.map((entry) => normalizeHost(typeof entry === 'string' ? entry : entry?.address ?? '')).filter(Boolean);
    case 'MX':
      return records
        .map((entry) => ({
          exchange: normalizeDnsName(typeof entry === 'string' ? entry : entry?.exchange),
          priority: Number(entry?.priority ?? 0)
        }))
        .filter((entry) => entry.exchange);
    case 'TXT':
      return records.map((entry) => (Array.isArray(entry) ? entry.join('') : String(entry ?? ''))).filter((entry) => entry.length > 0);
    default:
      return records.filter(Boolean);
  }
}

/**
 * Run one DNS query without throwing; a missing record, a resolver timeout or a scope refusal all
 * degrade to an empty answer with a diagnostic code.
 * @returns {Promise<{records: any[], error: string|null, evidenceId: string|null}>}
 */
async function safeQuery(ctx, fn, label) {
  try {
    const result = await fn();
    return {
      records: Array.isArray(result?.records) ? result.records : [],
      error: result?.error ?? null,
      evidenceId: result?.evidenceId ?? null,
      raw: result
    };
  } catch (error) {
    ctx.logger?.debug?.(`DNS ${label} failed: ${error?.message ?? error}`);
    return { records: [], error: error?.code ?? 'lookup-failed', evidenceId: null, raw: null };
  }
}

export default {
  id: 'recon.dns',
  phase: 'recon',
  title: 'DNS records and CNAME triage',
  description:
    'Inventories A/AAAA/CNAME/MX/NS/TXT/SOA records and flags CNAME chains pointing at provider suffixes with a known subdomain-takeover surface.',
  defaults: { maxChainDepth: 4 },
  async run(ctx) {
    const host = normalizeDnsName(ctx.target?.host ?? '');
    if (!host) {
      ctx.logger?.debug?.('recon.dns: target has no hostname, skipping');
      return { notes: ['dns: target has no hostname; nothing to resolve'] };
    }
    if (isIP(host)) {
      await ctx.addAsset({ type: 'ip', value: host });
      return { notes: [`dns: target ${host} is an IP literal; name records skipped`] };
    }
    if (!ctx.dns) {
      ctx.logger?.warn?.('recon.dns: ctx.dns is unavailable; skipping');
      return { notes: ['dns: resolver unavailable'] };
    }

    const apex = deriveApex(host);
    const domainAsset = await ctx.addAsset({ type: 'domain', value: apex, state: 'tested' });
    const hostAsset = host === apex
      ? domainAsset
      : await ctx.addAsset({ type: 'subdomain', value: host, parent: domainAsset, state: 'tested' });

    const answers = {};
    const evidence = [];
    const notes = [];

    // --- CNAME walk (bounded, follows the first target of each hop) -------------------------
    const chainTargets = [];
    const maxChainDepth = Math.max(1, Math.min(8, Number(ctx.options?.module?.maxChainDepth) || 4));
    let cursor = host;
    for (let depth = 0; depth < maxChainDepth; depth += 1) {
      if (ctx.signal?.aborted) break;
      if (budgetRemaining(ctx) < 5) {
        notes.push('dns: request budget low, CNAME walk truncated');
        break;
      }
      const result = await safeQuery(ctx, () => ctx.dns.resolveCname(cursor), `CNAME ${cursor}`);
      if (result.evidenceId) evidence.push(result.evidenceId);
      const targets = answerValues('CNAME', result.raw);
      if (targets.length === 0) break;
      chainTargets.push(...targets);
      cursor = targets[0];
    }
    answers.CNAME = chainTargets;

    // --- Address, mail and authority records ------------------------------------------------
    const collectors = [
      ['A', () => ctx.dns.resolve4(host)],
      ['AAAA', () => ctx.dns.resolve6(host)],
      ['MX', () => ctx.dns.resolveMx(host)],
      ['NS', () => ctx.dns.resolveNs(host)],
      ['TXT', () => ctx.dns.resolveTxt(host)],
      ['SOA', () => ctx.dns.resolveSoa(host)]
    ];
    for (const [rrtype, query] of collectors) {
      if (ctx.signal?.aborted) break;
      if (budgetRemaining(ctx) < 5) {
        notes.push(`dns: request budget low, ${rrtype} lookup skipped`);
        break;
      }
      const result = await safeQuery(ctx, query, `${rrtype} ${host}`);
      if (result.evidenceId) evidence.push(result.evidenceId);
      answers[rrtype] = answerValues(rrtype, result.raw);
      if (result.error && result.records.length === 0) ctx.logger?.debug?.(`${rrtype} ${host}: ${result.error}`);
    }

    // --- Assets for resolved addresses -------------------------------------------------------
    for (const address of answers.A ?? []) {
      await ctx.addAsset({ type: 'ip', value: address, parent: hostAsset, attributes: { family: 'IPv4', resolvedFrom: host } });
    }
    for (const address of answers.AAAA ?? []) {
      await ctx.addAsset({ type: 'ip', value: address, parent: hostAsset, attributes: { family: 'IPv6', resolvedFrom: host } });
    }

    // --- CNAME takeover triage ---------------------------------------------------------------
    const chain = analyzeCnameChain(host, chainTargets);
    if (chain.isDangling) {
      const candidates = chain.dangling.map((entry) => `${entry.target} (${entry.suffix})`);
      await ctx.addFinding({
        check: 'recon.dns.dangling-cname',
        title: `CNAME to takeover-prone provider: ${host}`,
        severity: 'high',
        confidence: 'possible',
        target: host,
        evidence,
        observed: [
          { key: 'cname-chain', value: chain.chain.join(' -> ') },
          { key: 'takeover-suffix', value: chain.dangling.map((entry) => entry.suffix).join(', ') }
        ],
        description:
          `The DNS name ${host} resolves through a CNAME chain that ends at ${candidates.join(', ')}. ` +
          'These providers let customers claim a name at the provider side, so if the resource behind this record has been ' +
          'released, an unauthorized party may be able to claim it and serve attacker-controlled content on the ' +
          `${host} origin. VANTAGE did not attempt to claim anything: this is a lead for manual validation, not proof of ` +
          'exploitation. Confirm at the provider whether the backing bucket/app/space still exists and is owned by the client.',
        impact:
          'A successful takeover lets an attacker host content on a trusted subdomain. That enables convincing phishing, ' +
          'cookie/domain-scoped credential theft for sibling services, malware delivery, and reputational damage; in some ' +
          'cases it can also intercept mail or bypass origin allow-lists that trust the hostname.',
        remediation:
          'Inventory every CNAME record that points at a third-party provider. Either keep the provider-side resource ' +
          'provisioned and owned by the organization, or delete the stale DNS record. Reclaim released resources before ' +
          'removing DNS where mail or app dependencies exist. Add an automated dangling-DNS check to the deployment ' +
          'pipeline and re-validate after every decommissioning.',
        references: [
          'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover',
          'https://cwe.mitre.org/data/definitions/16.html'
        ],
        cwe: ['CWE-16'],
        owasp: ['A05:2021']
      });
      ctx.logger?.warn?.(`dangling CNAME candidate for ${host}: ${chain.dangling.map((entry) => entry.target).join(', ')}`);
    } else if (chain.hops.length > 0) {
      await ctx.addFinding({
        check: 'recon.dns.cname-chain',
        title: `CNAME chain observed for ${host}`,
        severity: 'info',
        confidence: 'confirmed',
        target: host,
        evidence,
        observed: [{ key: 'cname-chain', value: chain.chain.join(' -> ') }],
        description:
          `The name ${host} is an alias: the chain ${chain.chain.join(' -> ')} was observed. Intermediate names are ` +
          'resolved by third-party infrastructure, so a change at the final provider can alter where this hostname points.',
        impact: 'No direct impact; recorded so dependencies on third-party DNS are visible during decommissioning and change review.',
        remediation:
          'No immediate action. Keep the CNAME chain documented, review it when a provider is retired, and include the ' +
          'final target in the dangling-DNS monitoring described for subdomain takeover.',
        references: ['https://www.rfc-editor.org/rfc/rfc1034#section-3.6.2'],
        cwe: [],
        owasp: ['A05:2021']
      });
    }

    // --- Inventory finding --------------------------------------------------------------------
    const inventory = summarizeDnsRecords(answers);
    if (inventory.total > 0) {
      await ctx.addFinding({
        check: 'recon.dns.record-inventory',
        title: `DNS inventory for ${host} (${inventory.total} records)`,
        severity: 'info',
        confidence: 'confirmed',
        target: host,
        evidence,
        observed: [
          ...inventory.types.map((type) => ({ key: type, value: String(inventory.counts[type]) })),
          ...(answers.MX?.length
            ? [{ key: 'mx', value: answers.MX.map((entry) => `${entry.priority} ${entry.exchange}`).join(', ') }]
            : []),
          ...(answers.NS?.length ? [{ key: 'ns', value: answers.NS.slice(0, 8).join(', ') }] : []),
          ...(answers.TXT?.length ? [{ key: 'txt', value: `${answers.TXT.length} TXT record(s)` }] : []),
          ...(answers.SOA?.length ? [{ key: 'soa', value: truncate(JSON.stringify(answers.SOA[0]), 300) }] : [])
        ],
        description:
          `Public DNS records for ${host} were enumerated through the engagement resolver: ` +
          `${inventory.types.map((type) => `${inventory.counts[type]} ${type}`).join(', ')}. ` +
          'This is the externally visible attack surface other checks build on; TXT and SOA values also feed the email-authentication review.',
        impact: 'No direct impact; incomplete or surprising DNS inventories are themselves an early indicator of shadow IT or stale infrastructure.',
        remediation:
          'No immediate action. Reconcile the inventory with the organization\'s asset register, remove records for retired ' +
          'services, and re-run the assessment after DNS changes so downstream checks cover the current surface.',
        references: ['https://www.rfc-editor.org/rfc/rfc1035'],
        cwe: [],
        owasp: ['A05:2021']
      });
    } else if (notes.length === 0) {
      notes.push(`dns: no records were returned for ${host}`);
    }

    ctx.logger?.info?.(`dns inventory for ${host}: ${inventory.total} record(s), chain depth ${chain.hops.length}`);
    return { notes };
  }
};
