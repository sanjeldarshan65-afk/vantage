/**
 * recon.subdomains — bounded subdomain discovery for wildcard-scoped targets.
 *
 * Only runs when the engagement scope names a wildcard (`*.example.com`) or when an operator passes
 * an explicit suffix. It first checks for wildcard DNS so the report can call out false positives,
 * then resolves a short fixed wordlist. There is no fuzzing: a static list of ~100 names, a hard
 * lookup cap and a budget guard keep the footprint small and predictable.
 */
import { randomBytes } from 'node:crypto';
import { ScopeError } from '../../core/errors.js';
import { normalizeHost } from '../../core/util.js';

/** Short, high-signal labels commonly used for public-facing and internal services. */
export const WORDLIST = Object.freeze([
  'www', 'api', 'app', 'admin', 'dev', 'staging', 'test', 'mail', 'portal', 'vpn', 'git', 'ci', 'cdn',
  'static', 'docs', 'blog', 'shop', 'support', 'status', 'db', 'sql', 'redis', 'jenkins', 'grafana',
  'kibana', 'prometheus', 'auth', 'sso', 'id', 'files', 'upload', 'assets', 'media', 'img', 'download',
  'internal', 'intranet', 'wiki', 'help', 'crm', 'erp', 'hr', 'jira', 'confluence', 'registry', 'docker',
  'k8s', 'kubernetes', 'monitoring', 'logs', 'metrics', 'ns1', 'ns2', 'mx1', 'smtp', 'imap', 'pop',
  'webmail', 'secure', 'login', 'checkout', 'pay', 'billing', 'invoices', 'reports', 'analytics',
  'dashboard', 'cache', 'proxy', 'lb', 'edge', 'origin', 'backup', 'old', 'new', 'v2', 'beta', 'demo',
  'sandbox', 'qa', 'uat', 'preprod', 'prod', 'stage', 'api-dev', 'api-staging', 'app-dev', 'app-staging',
  'www-dev', 'www-staging', 'mailer', 'mx', 'exchange', 'autodiscover', 'owa', 'remote', 'ldap', 'ftp',
  'sftp', 'gitlab', 'harbor', 'vault', 'sentry', 'splunk', 'kafka', 'rabbitmq'
]);

/**
 * Build the candidate host list for a suffix, de-duplicated and capped.
 * @param {string} suffix wildcard suffix, e.g. `example.com`
 * @param {string[]} words labels to try
 * @param {number} maxLookups hard cap on candidates
 * @returns {string[]} fully qualified candidate hostnames
 */
export function buildCandidateHosts(suffix, words = WORDLIST, maxLookups = 120) {
  const base = normalizeHost(suffix);
  const cap = Math.max(1, Number(maxLookups) || 120);
  const seen = new Set();
  const hosts = [];
  for (const rawWord of Array.isArray(words) ? words : []) {
    const word = normalizeHost(rawWord);
    if (!word || seen.has(word)) continue;
    seen.add(word);
    hosts.push(`${word}.${base}`);
    if (hosts.length >= cap) break;
  }
  return hosts;
}

/**
 * Build random labels used to test whether the suffix has wildcard DNS.
 * @param {string} suffix wildcard suffix
 * @param {number} [count] how many probes to generate
 * @param {() => string} [labelFactory] label generator (injectable for tests)
 * @returns {string[]} random hostnames that should not exist
 */
export function buildWildcardProbeHosts(suffix, count = 2, labelFactory = () => `vantage-wc-${randomBytes(6).toString('hex')}`) {
  const base = normalizeHost(suffix);
  const total = Math.max(1, Math.min(5, Number(count) || 2));
  const hosts = [];
  for (let index = 0; index < total; index += 1) {
    const label = normalizeHost(labelFactory(index));
    if (!label) continue;
    hosts.push(`${label}.${base}`);
  }
  return hosts;
}

/**
 * Decide whether the random probe answers prove wildcard DNS.
 * @param {Array<{addresses?: string[]}>} results resolver results for random names
 * @returns {{wildcard: boolean, addresses: string[]}}
 */
export function detectWildcardDns(results) {
  const addresses = [];
  for (const result of Array.isArray(results) ? results : []) {
    for (const address of result?.addresses ?? []) {
      if (address && !addresses.includes(address)) addresses.push(address);
    }
  }
  return { wildcard: addresses.length > 0, addresses };
}

/**
 * Normalize resolver results into discovered subdomains.
 * @param {Array<{host: string, addresses: string[], error?: string|null}>} results
 * @returns {Array<{host: string, addresses: string[]}>}
 */
export function collectResolved(results) {
  const discovered = [];
  for (const result of Array.isArray(results) ? results : []) {
    if (!result?.host) continue;
    const addresses = Array.isArray(result.addresses) ? result.addresses.filter(Boolean) : [];
    if (addresses.length > 0) discovered.push({ host: normalizeHost(result.host), addresses });
  }
  return discovered;
}

/** Remaining request budget, or Infinity when the context has no limiter (tests). */
function budgetRemaining(ctx) {
  const remaining = ctx?.guard?.limiter?.budget?.remaining;
  return Number.isFinite(remaining) ? remaining : Infinity;
}

/** Run at most `limit` workers over `items`, preserving result order. */
async function mapLimit(items, limit, worker, signal) {
  const results = new Array(items.length).fill(null);
  let cursor = 0;
  const size = Math.max(1, Math.min(limit, items.length));
  const runners = Array.from({ length: size }, async () => {
    while (cursor < items.length) {
      if (signal?.aborted) return;
      const index = cursor;
      cursor += 1;
      results[index] = await worker(items[index], index);
    }
  });
  await Promise.all(runners);
  return results;
}

export default {
  id: 'recon.subdomains',
  phase: 'recon',
  title: 'Subdomain discovery (wildcard scope)',
  description:
    'Checks for wildcard DNS on a scoped suffix, then resolves a bounded static wordlist and registers discovered subdomains as assets.',
  defaults: { suffix: null, maxLookups: 120, concurrency: 4 },
  async run(ctx) {
    const wildcardRule = (ctx.scope?.targets ?? []).find((rule) => rule?.type === 'wildcard');
    const optionSuffix = normalizeHost(ctx.options?.module?.suffix ?? '');
    const suffix = optionSuffix || normalizeHost(wildcardRule?.suffix ?? '');
    if (!suffix) {
      ctx.logger?.debug?.('recon.subdomains: no wildcard scope rule or suffix option, skipping');
      return { notes: ['subdomains: scope has no wildcard rule; discovery skipped'] };
    }
    const labels = suffix.split('.').filter(Boolean);
    if (labels.length < 2) {
      return { notes: [`subdomains: suffix "${suffix}" is too broad to enumerate safely; skipped`] };
    }
    if (!ctx.dns || typeof ctx.dns.lookup !== 'function') {
      return { notes: ['subdomains: resolver unavailable'] };
    }

    const domainAsset = await ctx.addAsset({ type: 'domain', value: suffix, state: 'tested' });
    const notes = [];

    // --- Wildcard DNS detection --------------------------------------------------------------
    const probeHosts = buildWildcardProbeHosts(suffix, 2);
    const probeResults = [];
    for (const host of probeHosts) {
      if (ctx.signal?.aborted) break;
      if (budgetRemaining(ctx) < 20) break;
      try {
        const result = await ctx.dns.lookup(host);
        probeResults.push({ host, addresses: Array.isArray(result?.addresses) ? result.addresses : [], error: result?.error ?? null });
      } catch (error) {
        if (error instanceof ScopeError) {
          notes.push(`subdomains: random probe ${host} refused by scope; discovery skipped`);
          return { notes };
        }
        ctx.logger?.debug?.(`wildcard probe for ${host} failed: ${error?.message ?? error}`);
        probeResults.push({ host, addresses: [], error: error?.code ?? 'lookup-failed' });
      }
    }
    const wildcard = detectWildcardDns(probeResults);
    if (wildcard.wildcard) {
      await ctx.addFinding({
        check: 'recon.subdomains.wildcard-dns',
        title: 'Wildcard DNS resolves nonexistent names',
        severity: 'low',
        confidence: 'confirmed',
        target: suffix,
        observed: [
          { key: 'probe', value: probeHosts.join(', ') },
          { key: 'wildcard-addresses', value: wildcard.addresses.join(', ') }
        ],
        description:
          `Randomly generated names under ${suffix} (${probeHosts.join(', ')}) resolve to ${wildcard.addresses.join(', ')}. ` +
          'The suffix therefore has a wildcard DNS record, which means any hostname under it appears to exist even when no ' +
          'service is behind it. Subdomain results in this report may include false positives: resolve each name and compare ' +
          'the address and certificate before treating it as a real asset.',
        impact:
          'Wildcard DNS can hide stale or dangling records, inflate the apparent attack surface, and complicate certificate ' +
          'validation and phishing investigations because arbitrary names appear legitimate.',
        remediation:
          'Confirm whether the wildcard record is required. Where it is, document it, restrict the certificate to the names ' +
          'actually served, and treat per-name discovery as advisory. Where it is not required, remove the wildcard and publish ' +
          'explicit records for each service so disappearance of a service is visible in DNS.',
        references: ['https://www.rfc-editor.org/rfc/rfc4592'],
        cwe: ['CWE-16'],
        owasp: ['A05:2021']
      });
      notes.push(`subdomains: wildcard DNS detected for ${suffix}; discoveries may be false positives`);
      ctx.logger?.warn?.(`wildcard DNS detected for ${suffix} (${wildcard.addresses.join(', ')})`);
    }

    // --- Wordlist discovery -------------------------------------------------------------------
    const maxLookups = Math.max(1, Math.min(500, Number(ctx.options?.module?.maxLookups) || 120));
    const concurrency = Math.max(1, Math.min(8, Number(ctx.options?.module?.concurrency) || 4));
    const candidates = buildCandidateHosts(suffix, WORDLIST, maxLookups);
    let scopeDenials = 0;
    let budgetStopped = false;

    const results = await mapLimit(
      candidates,
      concurrency,
      async (host) => {
        if (ctx.signal?.aborted) return { host, addresses: [], skipped: true };
        if (budgetRemaining(ctx) < 20) {
          budgetStopped = true;
          return { host, addresses: [], skipped: true };
        }
        try {
          const result = await ctx.dns.lookup(host);
          return { host, addresses: Array.isArray(result?.addresses) ? result.addresses : [], error: result?.error ?? null };
        } catch (error) {
          if (error instanceof ScopeError) {
            scopeDenials += 1;
            if (scopeDenials > 3) {
              notes.push(`subdomains: repeated scope refusals for *.${suffix}; enumeration stopped`);
              return { host, addresses: [], skipped: true, scopeDenied: true };
            }
            return { host, addresses: [], skipped: true };
          }
          ctx.logger?.debug?.(`subdomain lookup for ${host} failed: ${error?.message ?? error}`);
          return { host, addresses: [], error: error?.code ?? 'lookup-failed' };
        }
      },
      ctx.signal
    );

    if (budgetStopped) notes.push('subdomains: request budget low, enumeration truncated');
    const discovered = collectResolved(results);

    for (const entry of discovered) {
      await ctx.addAsset({
        type: 'subdomain',
        value: entry.host,
        parent: domainAsset,
        attributes: { addresses: entry.addresses }
      });
    }

    if (discovered.length > 0) {
      await ctx.addFinding({
        check: 'recon.subdomains.discovered',
        title: `${discovered.length} subdomain(s) discovered under ${suffix}`,
        severity: 'info',
        confidence: wildcard.wildcard ? 'likely' : 'confirmed',
        target: suffix,
        observed: [
          { key: 'count', value: String(discovered.length) },
          ...discovered.slice(0, 20).map((entry) => ({ key: 'subdomain', value: entry.host }))
        ],
        description:
          `Resolving a bounded static wordlist under ${suffix} produced ${discovered.length} name(s) with address records: ` +
          `${discovered.slice(0, 20).map((entry) => entry.host).join(', ')}${discovered.length > 20 ? ', …' : ''}. ` +
          'These names expand the assessed surface and are registered as assets for subsequent checks. Names beyond the ' +
          'wordlist may exist and are not covered by this result.' +
          (wildcard.wildcard ? ' Because wildcard DNS is present, verify each name against the wildcard addresses before treating it as a live service.' : ''),
        impact:
          'Exposed administrative, staging, CI or database interfaces increase the chance that an unpatched or weakly ' +
          'authenticated service is reachable; unused names also raise the value of a takeover attempt.',
        remediation:
          'Confirm ownership of every discovered name, retire records for services that should no longer exist, and place ' +
          'administrative interfaces behind VPN/SSO or IP allow-lists. Extend this list with the organization\'s own inventory ' +
          'and monitor certificate transparency logs for new names under the domain.',
        references: ['https://owasp.org/www-community/attacks/Subdomain_takeover'],
        cwe: [],
        owasp: ['A05:2021']
      });
      ctx.logger?.info?.(`subdomains: ${discovered.length} discovered under ${suffix}`);
    } else {
      notes.push(`subdomains: no names from the ${candidates.length}-entry wordlist resolved under ${suffix}`);
    }

    return { notes };
  }
};
