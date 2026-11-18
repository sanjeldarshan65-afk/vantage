/**
 * web.cors — checks whether the web root answers cross-origin requests too generously.
 *
 * Three harmless, read-only probes are sent through the guard: a GET carrying a reserved-TLD
 * `Origin`, an OPTIONS preflight, and a GET with `Origin: null` (the sandboxed-iframe origin).
 * The `.invalid` TLD is reserved by RFC 2606, so the fake origin can never resolve to a real host.
 *
 * Pure grading helper `analyzeCors(getRes, preflightRes, opts)` is exported for unit tests.
 */

const PROBE_ORIGIN = 'https://vantage-probe.invalid';
const NULL_ORIGIN = 'null';
const WILDCARD_SUBDOMAIN_RE = /^https?:\/\/\*\.[^/]+$/i;

/** Read a header from either a guarded fetch result or a plain `{headers}` fixture. */
function headerOf(response, name) {
  if (!response) return null;
  if (typeof response.header === 'function') {
    const value = response.header(name);
    return value == null ? null : String(value);
  }
  const headers = response.headers ?? response.response?.headers;
  if (!headers) return null;
  const value = headers[String(name).toLowerCase()];
  if (value == null) return null;
  return Array.isArray(value) ? value.join(', ') : String(value);
}

/** Evidence id of a guarded response (or null for plain fixtures). */
function evidenceOf(response) {
  if (!response) return null;
  if (typeof response.evidence === 'string') return response.evidence;
  return response.evidence?.id ?? null;
}

/** True when the `Access-Control-Allow-Credentials` header enables credentials. */
function credentialsAllowed(response) {
  return String(headerOf(response, 'access-control-allow-credentials') ?? '').trim().toLowerCase() === 'true';
}

/**
 * Grade CORS responses.
 *
 * @param {object|null} getRes guarded response to the cross-origin GET
 * @param {object|null} preflightRes guarded response to the OPTIONS preflight
 * @param {{origin?: string, nullOriginRes?: object|null, url?: string}} [options]
 * @returns {{findings: object[]}}
 */
export function analyzeCors(getRes, preflightRes, { origin = PROBE_ORIGIN, nullOriginRes = null, url = '' } = {}) {
  const target = String(url ?? '');
  const probeOrigin = String(origin || PROBE_ORIGIN);
  const findings = [];
  const push = (slug, severity, title, fields) => {
    findings.push({
      check: `web.cors.${slug}`,
      title,
      severity,
      confidence: 'confirmed',
      target,
      ...fields
    });
  };

  /** @type {{label: string, acao: string|null, credentials: boolean, evidence: string|null}[]} */
  const assessments = [
    { label: 'GET', acao: headerOf(getRes, 'access-control-allow-origin'), credentials: credentialsAllowed(getRes), evidence: evidenceOf(getRes) },
    { label: 'OPTIONS preflight', acao: headerOf(preflightRes, 'access-control-allow-origin'), credentials: credentialsAllowed(preflightRes), evidence: evidenceOf(preflightRes) },
    { label: 'Origin: null GET', acao: headerOf(nullOriginRes, 'access-control-allow-origin'), credentials: credentialsAllowed(nullOriginRes), evidence: evidenceOf(nullOriginRes) }
  ].filter((entry) => entry.acao != null);

  const withEvidence = (entries) => [...new Set(entries.map((entry) => entry.evidence).filter(Boolean))];

  /* ------------------------------------------------ arbitrary origin reflection */
  const reflected = assessments.filter((entry) => entry.acao === probeOrigin);
  if (reflected.length > 0) {
    const credentialed = reflected.filter((entry) => entry.credentials);
    if (credentialed.length > 0) {
      push('reflected-origin-with-credentials', 'high', 'CORS reflects an arbitrary origin with credentials', {
        evidence: withEvidence(credentialed),
        observed: [
          { key: 'probe-origin', value: probeOrigin },
          { key: 'access-control-allow-origin', value: probeOrigin },
          { key: 'access-control-allow-credentials', value: 'true' },
          { key: 'responses', value: credentialed.map((entry) => entry.label).join(', ') }
        ],
        description:
          'The server echoes an arbitrary attacker-chosen origin in `Access-Control-Allow-Origin` and answers ' +
          '`Access-Control-Allow-Credentials: true`. Because the reflected value is not an allow-listed origin, ' +
          'any site on the internet is granted credentialed access to this endpoint.',
        impact:
          'Any web page on the internet can make a signed-in victim\'s browser read this origin\'s responses and ' +
          'send them to the attacker. Combined with an authenticated cookie or HTTP auth, that is a complete ' +
          'cross-site data theft primitive (account data, CSRF tokens, API responses).',
        remediation:
          'Validate the `Origin` header against an explicit allow-list of trusted origins and only reflect an ' +
          'exact match; never reflect an unknown origin. Send `Access-Control-Allow-Credentials: true` only for ' +
          'those exact origins, and never together with a wildcard. Example (Express): ' +
          "`origin: (origin, cb) => cb(null, ALLOWED.includes(origin))`.",
        references: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
          'https://portswigger.net/web-security/cors'
        ],
        cwe: ['CWE-942'],
        owasp: ['A05:2021']
      });
    } else {
      push('reflected-origin', 'info', 'CORS reflects an arbitrary origin without credentials', {
        evidence: withEvidence(reflected),
        observed: [
          { key: 'probe-origin', value: probeOrigin },
          { key: 'access-control-allow-origin', value: probeOrigin },
          { key: 'access-control-allow-credentials', value: 'false' },
          { key: 'responses', value: reflected.map((entry) => entry.label).join(', ') }
        ],
        description:
          'The server echoes an arbitrary attacker-chosen origin in `Access-Control-Allow-Origin`, although ' +
          'credentials are not enabled. Any origin can read the response, but the victim\'s cookies and ' +
          'authorization headers are not attached.',
        impact:
          'Cross-origin reading of this endpoint is possible for any site. If the endpoint ever returns ' +
          'per-user data based on a query parameter, IP address or other ambient authority, that data is exposed.',
        remediation:
          'Reflect only exact, allow-listed origins instead of echoing whatever `Origin` arrives; if the endpoint ' +
          'is genuinely public, return a static `Access-Control-Allow-Origin: *` instead of reflection.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://portswigger.net/web-security/cors'],
        cwe: ['CWE-942'],
        owasp: ['A05:2021']
      });
    }
  }

  /* ------------------------------------------------------------- null origin */
  const nullReflected = assessments.filter((entry) => entry.acao === NULL_ORIGIN);
  if (nullReflected.length > 0) {
    const credentialed = nullReflected.filter((entry) => entry.credentials);
    push('null-origin-reflected', credentialed.length > 0 ? 'high' : 'medium', 'CORS trusts the null origin', {
      evidence: withEvidence(nullReflected),
      observed: [
        { key: 'request-origin', value: NULL_ORIGIN },
        { key: 'access-control-allow-origin', value: NULL_ORIGIN },
        { key: 'access-control-allow-credentials', value: credentialed.length > 0 ? 'true' : 'false' }
      ],
      description:
        'A request sent with `Origin: null` was accepted, and the server echoes `null` back. The null origin is ' +
        'produced by sandboxed iframes, `data:` URLs and some redirect flows, so it is trivial for an attacker ' +
        'to obtain one.',
      impact:
        'A sandboxed `data:`/`about:blank` frame on an attacker page can make credentialed cross-origin requests ' +
        'and read the responses, bypassing origin isolation entirely.',
      remediation:
        'Never allow-list the literal `null` origin. Reject requests whose `Origin` is missing, `null`, or not ' +
        'an exact match for a trusted scheme+host+port.',
      references: ['https://portswigger.net/web-security/cors', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
      cwe: ['CWE-942'],
      owasp: ['A05:2021']
    });
  }

  /* ---------------------------------------------------------- wildcard origin */
  const wildcard = assessments.filter((entry) => entry.acao === '*');
  if (wildcard.length > 0) {
    const credentialed = wildcard.filter((entry) => entry.credentials);
    if (credentialed.length > 0) {
      push('wildcard-with-credentials', 'high', 'CORS wildcard origin is combined with credentialed access', {
        evidence: withEvidence(credentialed),
        observed: [
          { key: 'access-control-allow-origin', value: '*' },
          { key: 'access-control-allow-credentials', value: 'true' },
          { key: 'responses', value: credentialed.map((entry) => entry.label).join(', ') }
        ],
        description:
          'The server answers with `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`. ' +
          'Browsers reject this combination, so credentialed cross-origin requests fail — but the configuration ' +
          'shows that origin checks are not understood, and some clients/proxies still act on it.',
        impact:
          'Either credential sharing is intentionally broken (functionality loss for legitimate cross-origin ' +
          'apps) or a non-browser client honours the wildcard and trusts data from any origin.',
        remediation:
          'Choose one model: a static `*` for fully public, credential-free resources; or an exact allow-list of ' +
          'reflected origins together with `Access-Control-Allow-Credentials: true`. Never mix `*` with credentials.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
        cwe: ['CWE-942'],
        owasp: ['A05:2021']
      });
    } else {
      push('wildcard-origin', 'low', 'CORS wildcard origin policy is enabled', {
        evidence: withEvidence(wildcard),
        observed: [
          { key: 'access-control-allow-origin', value: '*' },
          { key: 'access-control-allow-credentials', value: 'false' },
          { key: 'responses', value: wildcard.map((entry) => entry.label).join(', ') }
        ],
        description:
          'The endpoint returns `Access-Control-Allow-Origin: *`, so any origin can read its responses. ' +
          'No credentials are shared, so this is only a problem if the response contains data that should not ' +
          'be world-readable.',
        impact:
          'Any website can fetch and read this resource on behalf of the visitor (including intranet-only data ' +
          'reachable through the visitor\'s network position).',
        remediation:
          'If the data is truly public this is acceptable — document it. Otherwise replace the wildcard with an ' +
          'exact origin allow-list and drop `Access-Control-Allow-Credentials` from responses that do not need it.',
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS', 'https://portswigger.net/web-security/cors'],
        cwe: ['CWE-942'],
        owasp: ['A05:2021']
      });
    }
  }

  /* -------------------------------------------------- wildcard subdomain echo */
  const wildcardSubdomain = assessments.filter((entry) => WILDCARD_SUBDOMAIN_RE.test(entry.acao));
  if (wildcardSubdomain.length > 0) {
    push('wildcard-subdomain', 'medium', 'CORS policy trusts a wildcard subdomain pattern', {
      evidence: withEvidence(wildcardSubdomain),
      observed: [
        { key: 'probe-origin', value: probeOrigin },
        { key: 'access-control-allow-origin', value: wildcardSubdomain[0].acao }
      ],
      description:
        'The server returns a wildcard subdomain as the allowed origin (for example `https://*.example.test`). ' +
        'The CORS specification only allows a literal `*` or an exact origin; wildcard subdomains are rejected ' +
        'by browsers and rely on fragile custom matching.',
      impact:
        'If the intent is to trust every subdomain, any subdomain takeover or user-controlled subdomain becomes ' +
        'a trusted origin. Browsers that reject the value can also silently break the intended integration.',
      remediation:
        'Resolve the request `Origin` to an exact match against a maintained allow-list (or use a strict ' +
        'regex that pins the scheme, label count and port) and never return a `*` inside the origin value.',
      references: ['https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS'],
      cwe: ['CWE-942'],
      owasp: ['A05:2021']
    });
  }

  return { findings };
}

export default {
  id: 'web.cors',
  phase: 'web',
  title: 'CORS policy',
  description: 'Tests cross-origin resource sharing with reserved-TLD, null and preflight requests; grades reflected and wildcard origins.',
  defaults: {},
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) {
      ctx.logger.warn?.('no HTTP response from the web target; skipping CORS checks');
      return;
    }
    const base = probe.url;

    const request = async (method, headers, label) => {
      try {
        return await ctx.guard.fetch(base, { method, headers, maxBytes: 8192, module: 'web.cors' });
      } catch (error) {
        ctx.logger.debug?.(`CORS ${label} probe failed: ${error.message}`);
        return null;
      }
    };

    const getRes = await request('GET', { Origin: PROBE_ORIGIN }, 'GET');
    const preflightRes = await request(
      'OPTIONS',
      { Origin: PROBE_ORIGIN, 'Access-Control-Request-Method': 'GET' },
      'preflight'
    );
    const nullOriginRes = await request('GET', { Origin: NULL_ORIGIN }, 'null-origin');

    if (!getRes && !preflightRes && !nullOriginRes) {
      ctx.logger.warn?.('all CORS probes failed; nothing to grade');
      return;
    }

    const { findings } = analyzeCors(getRes, preflightRes, {
      origin: PROBE_ORIGIN,
      nullOriginRes,
      url: base
    });
    for (const finding of findings) await ctx.addFinding(finding);
    ctx.logger.info?.(`CORS probing produced ${findings.length} finding(s)`);
    return { notes: [`CORS probes: GET=${Boolean(getRes)} preflight=${Boolean(preflightRes)} null=${Boolean(nullOriginRes)}`] };
  }
};
