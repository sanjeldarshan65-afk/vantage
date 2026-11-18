/**
 * web.cookies — audits the `Set-Cookie` flags of an in-scope web target.
 *
 * Reads the cookies returned by the guarded web-root probe and grades Secure, HttpOnly, SameSite,
 * Domain scope and the `__Host-` / `__Secure-` prefix contracts. Values are never recorded: the
 * parser deliberately returns flags only, and every observation names the cookie, not its secret.
 *
 * Pure helpers (`splitCookieAttributes`, `analyzeSetCookie`, `auditCookie`, `auditCookies`) are
 * exported for unit tests; only `run()` touches the guard.
 */

const REFS = Object.freeze({
  mdnSetCookie: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie',
  mdnPrefixes: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes',
  owaspWstg: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes',
  owaspSession: 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'
});

/**
 * Session-like cookie names. Deliberately broad: the goal is to find cookies whose theft matters,
 * and a false positive costs one low-severity finding while a false negative hides a session token.
 */
export const SESSION_NAME_RE = /(sess|sid|auth|token|jwt|connect\.sid|jsessionid|phpsessid)/i;

/**
 * Split a `Set-Cookie` header on semicolons, ignoring semicolons inside a quoted value.
 * @param {string} raw
 * @returns {string[]}
 */
export function splitCookieAttributes(raw) {
  const parts = [];
  let current = '';
  let quoted = false;
  for (const char of String(raw ?? '')) {
    if (char === '"') {
      quoted = !quoted;
      current += char;
      continue;
    }
    if (char === ';' && !quoted) {
      parts.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  parts.push(current);
  return parts.map((part) => part.trim()).filter(Boolean);
}

/**
 * Parse one raw `Set-Cookie` header into its name and security-relevant flags.
 * The cookie value is intentionally not returned.
 *
 * @param {string} raw
 * @returns {{name: string, flags: {secure: boolean, httpOnly: boolean,
 *   sameSite: 'strict'|'lax'|'none'|'absent', domain: string|null, path: string|null,
 *   maxAge: number|null, expires: string|null}}}
 */
export function analyzeSetCookie(raw) {
  const flags = {
    secure: false,
    httpOnly: false,
    sameSite: 'absent',
    domain: null,
    path: null,
    maxAge: null,
    expires: null
  };
  const parts = splitCookieAttributes(raw);
  const head = parts.shift() ?? '';
  const equals = head.indexOf('=');
  const name = (equals === -1 ? head : head.slice(0, equals)).trim();
  for (const part of parts) {
    const index = part.indexOf('=');
    const key = (index === -1 ? part : part.slice(0, index)).trim().toLowerCase();
    const value = index === -1 ? '' : part.slice(index + 1).trim().replace(/^"(.*)"$/, '$1');
    switch (key) {
      case 'secure':
        flags.secure = true;
        break;
      case 'httponly':
        flags.httpOnly = true;
        break;
      case 'samesite': {
        const normalized = value.toLowerCase();
        flags.sameSite = normalized === 'strict' || normalized === 'lax' || normalized === 'none' ? normalized : 'absent';
        break;
      }
      case 'domain':
        flags.domain = value || null;
        break;
      case 'path':
        flags.path = value || null;
        break;
      case 'max-age': {
        if (/^-?\d+$/.test(value)) flags.maxAge = Number(value);
        break;
      }
      case 'expires':
        flags.expires = value || null;
        break;
      default:
        // Unknown attributes (Partitioned, Priority, ...) are not security-graded here.
        break;
    }
  }
  return { name, flags };
}

/** Hostname of a URL, or '' when it cannot be parsed. */
function hostnameOf(url) {
  try {
    return new URL(String(url)).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** Human-readable flag summary used in `observed` (never contains the cookie value). */
function flagSummary(flags) {
  return [
    `Secure=${flags.secure}`,
    `HttpOnly=${flags.httpOnly}`,
    `SameSite=${flags.sameSite}`,
    `Domain=${flags.domain ?? 'host-only'}`,
    `Path=${flags.path ?? 'default'}`
  ].join('; ');
}

function evidenceList(evidence) {
  return (Array.isArray(evidence) ? evidence : evidence ? [evidence] : []).filter(Boolean);
}

/**
 * Grade one parsed cookie.
 *
 * @param {{name: string, flags: object}} cookie
 * @param {{scheme?: string, url?: string, host?: string|null, evidence?: string|string[]|null,
 *   sessionLike?: boolean}} [options]
 * @returns {object[]} finding partials (no target asset wiring needed)
 */
export function auditCookie(cookie, { scheme = 'https', url = '', host = null, evidence = null, sessionLike = null } = {}) {
  const name = String(cookie?.name ?? '').trim();
  const flags = cookie?.flags ?? {};
  const target = String(url ?? '');
  const hostname = String(host ?? '').toLowerCase() || hostnameOf(target);
  const evidenceIds = evidenceList(evidence);
  const sessionCookie = sessionLike == null ? SESSION_NAME_RE.test(name) : Boolean(sessionLike);
  const observed = [
    { key: 'cookie', value: name || '<unnamed>' },
    { key: 'flags', value: flagSummary(flags) }
  ];
  const findings = [];
  const push = (slug, severity, title, fields) => {
    findings.push({
      check: `web.cookies.${slug}`,
      title,
      severity,
      confidence: 'confirmed',
      target,
      evidence: [...evidenceIds],
      observed,
      ...fields
    });
  };

  if (String(scheme).toLowerCase() === 'https' && !flags.secure) {
    push('missing-secure', 'medium', `Cookie "${name || '<unnamed>'}" is set without the Secure attribute`, {
      description:
        'The cookie is delivered without `Secure`. The browser will therefore also send it over plain-HTTP ' +
        'requests to this host, should any exist.',
      impact:
        'An on-path attacker who can force or observe an HTTP request to the host receives the cookie in ' +
        'cleartext and can replay it, leading to session or authentication-token theft.',
      remediation:
        'Add the `Secure` attribute to the `Set-Cookie` header (e.g. `Set-Cookie: ' + name + '=...; Secure; HttpOnly; SameSite=Lax`).',
      references: [REFS.owaspWstg, REFS.mdnSetCookie],
      cwe: ['CWE-614'],
      owasp: ['A05:2021']
    });
  }

  if (sessionCookie && !flags.httpOnly) {
    push('missing-httponly', 'low', `Session cookie "${name || '<unnamed>'}" is readable from JavaScript`, {
      description:
        'This cookie looks like a session/authentication cookie but is not marked `HttpOnly`, so any script ' +
        'running in the page can read it through `document.cookie`.',
      impact:
        'An XSS flaw anywhere on the site escalates from script execution to full session takeover: the payload ' +
        'can exfiltrate the cookie, and the attacker can impersonate the user until it expires.',
      remediation: 'Add the `HttpOnly` attribute to the session cookie (`Set-Cookie: ...; HttpOnly`).',
      references: [REFS.owaspSession, REFS.owaspWstg],
      cwe: ['CWE-1004'],
      owasp: ['A05:2021']
    });
  }

  if (flags.sameSite === 'none' && !flags.secure) {
    push('samesite-none-without-secure', 'high', `Cookie "${name || '<unnamed>'}" uses SameSite=None without Secure`, {
      description:
        'The cookie explicitly asks to be sent on cross-site requests (`SameSite=None`) but omits `Secure`. ' +
        'Current browsers reject this combination, so the cookie silently fails; older clients send it in states ' +
        'where it can be captured.',
      impact:
        'Behaviour is browser-dependent: where accepted, the cookie is exposed to cross-site request forgery and ' +
        'cleartext interception; where rejected, cross-site flows that depend on the cookie break.',
      remediation:
        'Always pair `SameSite=None` with `Secure`: `Set-Cookie: ...; Secure; SameSite=None`. If cross-site ' +
        'delivery is not needed, use `SameSite=Lax` instead.',
      references: [REFS.mdnSetCookie, REFS.owaspWstg],
      cwe: ['CWE-1275', 'CWE-614'],
      owasp: ['A01:2021']
    });
  }

  if (flags.sameSite === 'absent') {
    push('samesite-absent', 'low', `Cookie "${name || '<unnamed>'}" does not set the SameSite attribute`, {
      description:
        'The cookie has no `SameSite` attribute, so the browser applies its default policy. Chrome and Edge ' +
        'default to `Lax`; older or differently configured clients may still send it cross-site.',
      impact:
        'On clients with no default, the cookie is attached to cross-site form posts and image loads, exposing ' +
        'state-changing requests to CSRF and enabling cross-site tracking.',
      remediation:
        'Set an explicit policy: `SameSite=Lax` for ordinary session cookies, `SameSite=Strict` for ' +
        'high-value flows. Use `SameSite=None; Secure` only when a genuine cross-site embed requires it.',
      references: [REFS.mdnSetCookie, REFS.owaspWstg],
      cwe: ['CWE-1275'],
      owasp: ['A01:2021']
    });
  }

  if (flags.domain) {
    const domain = flags.domain.toLowerCase().replace(/^\./, '');
    if (hostname && domain !== hostname && hostname.endsWith(`.${domain}`)) {
      push('broad-domain', 'low', `Cookie "${name || '<unnamed>'}" is scoped to a parent domain`, {
        description:
          `The cookie sets \`Domain=${domain}\` while it was served by \`${hostname}\`, so every subdomain of ` +
          `\`${domain}\` can read it.`,
        impact:
          'A compromised, staging or third-party-hosted subdomain can set or read this cookie, defeating the ' +
          'single-origin isolation the application expects.',
        remediation:
          'Remove the `Domain` attribute so the cookie is host-only, or scope it to the narrowest subdomain that ' +
          'actually needs to share it.',
        references: [REFS.owaspWstg, REFS.owaspSession],
        cwe: ['CWE-1275'],
        owasp: ['A05:2021']
      });
    }
  }

  if (name.startsWith('__Host-')) {
    const violations = [];
    if (!flags.secure) violations.push('missing Secure');
    if (flags.domain) violations.push(`sets Domain=${flags.domain}`);
    if ((flags.path ?? '').toLowerCase() !== '/') violations.push(`Path=${flags.path ?? 'default'} instead of /`);
    if (violations.length > 0) {
      push('host-prefix-violation', 'medium', `Cookie "${name}" violates the __Host- prefix contract`, {
        description:
          'A `__Host-` cookie must be set with `Secure`, `Path=/` and no `Domain` attribute. This response ' +
          `breaks the contract: ${violations.join('; ')}.`,
        impact:
          'Browsers reject the cookie (breaking the feature) or, where accepted, lose the guarantee that the ' +
          'cookie cannot be overwritten by a sibling subdomain.',
        remediation:
          'Set `__Host-` cookies as `Set-Cookie: __Host-name=...; Secure; Path=/; HttpOnly; SameSite=Lax` and ' +
          'remove the `Domain` attribute.',
        references: [REFS.mdnPrefixes, REFS.mdnSetCookie],
        cwe: ['CWE-614'],
        owasp: ['A05:2021']
      });
    }
  } else if (name.startsWith('__Secure-') && !flags.secure) {
    push('secure-prefix-violation', 'medium', `Cookie "${name}" violates the __Secure- prefix contract`, {
      description: 'A `__Secure-` cookie must be set with the `Secure` attribute; this response omits it.',
      impact:
        'Browsers reject the cookie, so the feature that depends on it silently fails; clients that accept it ' +
        'send the cookie over cleartext.',
      remediation: `Add \`Secure\` to the cookie: \`Set-Cookie: ${name}=...; Secure; HttpOnly; SameSite=Lax\`.`,
      references: [REFS.mdnPrefixes, REFS.mdnSetCookie],
      cwe: ['CWE-614'],
      owasp: ['A05:2021']
    });
  }

  return findings;
}

/** Phrase used to build the aggregated title for a cookie check. */
function aggregatePhrase(check) {
  switch (check) {
    case 'web.cookies.missing-secure':
      return 'are set without the Secure attribute';
    case 'web.cookies.missing-httponly':
      return 'are session cookies without HttpOnly';
    case 'web.cookies.samesite-none-without-secure':
      return 'use SameSite=None without Secure';
    case 'web.cookies.samesite-absent':
      return 'do not set SameSite';
    case 'web.cookies.broad-domain':
      return 'are scoped to a parent domain';
    case 'web.cookies.host-prefix-violation':
      return 'violate the __Host- prefix contract';
    case 'web.cookies.secure-prefix-violation':
      return 'violate the __Secure- prefix contract';
    default:
      return 'share the same cookie misconfiguration';
  }
}

/**
 * Fold per-cookie findings into one finding per issue type. Used when a response sets many cookies
 * so the report does not drown in near-identical rows.
 * @param {object[]} findings
 * @returns {object[]}
 */
export function aggregateCookieFindings(findings) {
  const groups = new Map();
  for (const finding of findings) {
    const group = groups.get(finding.check) ?? { template: finding, names: [], evidence: new Set() };
    const name = (finding.observed ?? []).find((item) => item.key === 'cookie')?.value;
    if (name && !group.names.includes(name)) group.names.push(name);
    for (const id of finding.evidence ?? []) group.evidence.add(id);
    groups.set(finding.check, group);
  }
  const aggregated = [];
  for (const { template, names, evidence } of groups.values()) {
    const shown = names.slice(0, 10);
    aggregated.push({
      ...template,
      title: `${names.length} cookie${names.length === 1 ? '' : 's'} ${aggregatePhrase(template.check)}`,
      observed: [
        ...shown.map((name) => ({ key: 'cookie', value: name })),
        ...(names.length > shown.length ? [{ key: 'additional', value: `${names.length - shown.length} more cookie(s)` }] : [])
      ],
      evidence: [...evidence]
    });
  }
  return aggregated;
}

/**
 * Parse and grade a whole response's `Set-Cookie` collection.
 *
 * @param {string[]} rawCookies raw Set-Cookie header values
 * @param {{scheme?: string, url?: string, host?: string|null, evidence?: string|string[]|null,
 *   aggregateThreshold?: number}} [options]
 * @returns {{cookies: object[], findings: object[]}}
 */
export function auditCookies(rawCookies, options = {}) {
  const raws = (Array.isArray(rawCookies) ? rawCookies : []).filter((raw) => typeof raw === 'string' && raw.trim() !== '');
  const cookies = raws.map(analyzeSetCookie);
  const findings = cookies.flatMap((cookie) => auditCookie(cookie, options));
  const threshold = Number(options.aggregateThreshold ?? 8);
  if (cookies.length > threshold && findings.length > 1) {
    return { cookies, findings: aggregateCookieFindings(findings) };
  }
  return { cookies, findings };
}

export default {
  id: 'web.cookies',
  phase: 'web',
  title: 'Cookie security flags',
  description: 'Grades Set-Cookie flags: Secure, HttpOnly, SameSite, Domain scope and __Host-/__Secure- prefix compliance.',
  defaults: {},
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) {
      ctx.logger.warn?.('no HTTP response from the web target; skipping cookie audit');
      return;
    }
    const rawCookies = Array.isArray(probe.setCookie) ? probe.setCookie : [];
    if (rawCookies.length === 0) {
      ctx.logger.info?.('the web root set no cookies');
      return { notes: ['web root response set no cookies'] };
    }
    const { cookies, findings } = auditCookies(rawCookies, {
      scheme: probe.scheme,
      url: probe.url,
      evidence: probe.session?.evidence?.id ?? null
    });
    for (const finding of findings) await ctx.addFinding(finding);
    ctx.logger.info?.(`audited ${cookies.length} cookie(s), produced ${findings.length} finding(s)`);
    return { notes: [`audited ${cookies.length} cookie(s)`] };
  }
};
