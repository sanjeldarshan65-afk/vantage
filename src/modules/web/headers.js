/**
 * web.headers — grades the HTTP response security headers of an in-scope web target.
 *
 * Non-destructive by construction: one guarded GET of the web root, plus one guarded GET of the
 * plain-HTTP origin when the target answers over HTTPS (to prove that cleartext requests are
 * redirected). Every finding references evidence captured by the guard.
 *
 * The grading logic is exported as pure helpers (`normalizeHeaders`, `parseHsts`, `parseCsp`,
 * `analyzeHeaders`, `analyzeHttpsRedirect`) so it can be unit-tested without any network.
 */

const OWASP_SECURE_HEADERS = 'https://owasp.org/www-project-secure-headers/';
const HSTS_MIN_MAX_AGE = 15552000; // 180 days
const HTML_CT_RE = /(?:text\/html|application\/xhtml\+xml)/i;
const SERVER_VERSION_RE = /^([A-Za-z][\w.+-]*?)\/(\d+(?:\.\d+){1,3})/;

/** Keep header/observation text bounded when a target sends something absurd. */
function clip(value, max = 300) {
  const text = String(value ?? '');
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

/**
 * Normalize raw response headers to lowercase names and string values.
 * The HTTP layer guarantees lowercase names, but tests and exotic servers may not.
 * @param {Record<string, string|string[]>} headers
 * @returns {Record<string, string>}
 */
export function normalizeHeaders(headers = {}) {
  const out = {};
  if (!headers || typeof headers !== 'object') return out;
  for (const [name, value] of Object.entries(headers)) {
    const key = String(name).toLowerCase();
    if (value == null) continue;
    out[key] = Array.isArray(value) ? value.map((item) => String(item)).join(', ') : String(value);
  }
  return out;
}

/**
 * First value of a header from a normalized map, or null when absent/blank.
 * @param {Record<string, string>} headers
 * @param {string} name
 * @returns {string|null}
 */
export function headerValue(headers, name) {
  const value = headers?.[String(name).toLowerCase()];
  if (value == null) return null;
  const text = String(value).trim();
  return text === '' ? null : text;
}

/** True when the response is (or may be) an HTML document. */
function isHtmlLike(headers) {
  const contentType = headerValue(headers, 'content-type');
  if (!contentType) return true; // unknown: grade the browser-facing checks, better to review than miss
  return HTML_CT_RE.test(contentType);
}

/**
 * Parse a `Strict-Transport-Security` value.
 * @param {string} value
 * @returns {{directives: Map<string,string>, maxAge: number|null, includeSubDomains: boolean, preload: boolean}}
 */
export function parseHsts(value) {
  const directives = new Map();
  for (const part of String(value ?? '').split(';')) {
    const token = part.trim();
    if (!token) continue;
    const equals = token.indexOf('=');
    const key = (equals === -1 ? token : token.slice(0, equals)).trim().toLowerCase();
    if (!key) continue;
    const raw = equals === -1 ? '' : token.slice(equals + 1).trim().replace(/^"|"$/g, '');
    directives.set(key, raw);
  }
  const maxAgeRaw = directives.get('max-age');
  const maxAge = maxAgeRaw != null && /^\d+$/.test(maxAgeRaw) ? Number(maxAgeRaw) : null;
  return {
    directives,
    maxAge,
    includeSubDomains: directives.has('includesubdomains'),
    preload: directives.has('preload')
  };
}

/**
 * Parse a Content-Security-Policy value into directive name → source list.
 * Malformed tokens are skipped rather than thrown away: the target controls this string.
 * @param {string} value
 * @returns {{directives: Record<string, string[]>, raw: string}}
 */
export function parseCsp(value) {
  const directives = {};
  const raw = String(value ?? '').trim();
  if (!raw) return { directives, raw };
  for (const part of raw.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens.shift().toLowerCase();
    if (!/^[a-z][a-z0-9-]*$/.test(name)) continue;
    directives[name] = tokens.map((token) => token.toLowerCase());
  }
  return { directives, raw };
}

/** Directives that matter when grading a policy's strength. */
const GRADEABLE_SOURCES = ['default-src', 'script-src', 'style-src', 'object-src'];

/**
 * Grade response headers.
 *
 * Browser-only protections (CSP, clickjacking, COOP/COEP) are graded for HTML-ish responses;
 * transport and disclosure headers are graded for every response.
 *
 * @param {Record<string, string|string[]>} headers raw response headers
 * @param {{scheme?: string, url?: string, evidence?: string|string[]|null}} [options]
 * @returns {{findings: object[]}}
 */
/**
 * CSP delivered by `<meta http-equiv="Content-Security-Policy">`, if the page has one.
 * Only the document head is searched, and only the first policy is returned.
 * @param {string} html
 * @returns {string|null}
 */
export function metaCspFromHtml(html) {
  const head = String(html ?? '').slice(0, 65536);
  for (const tag of head.match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/http-equiv\s*=\s*["']?content-security-policy["'\s>]/i.test(tag)) continue;
    const content = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    if (content) return (content[1] ?? content[2]).trim() || null;
  }
  return null;
}

/**
 * Referrer policy from `<meta name="referrer">`, if present.
 * @param {string} html
 * @returns {string|null}
 */
export function metaReferrerFromHtml(html) {
  for (const tag of String(html ?? '').slice(0, 65536).match(/<meta\b[^>]*>/gi) ?? []) {
    if (!/\bname\s*=\s*["']?referrer["'\s>]/i.test(tag)) continue;
    const content = /\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(tag);
    if (content) return (content[1] ?? content[2]).trim() || null;
  }
  return null;
}

/**
 * Cross-origin scripts and stylesheets loaded without an `integrity` attribute.
 * Same-origin resources are skipped: SRI only protects against a compromised third party.
 * @returns {object|null} one finding listing every unprotected resource
 */
export function analyzeSubresourceIntegrity(html, { url = '', evidence = null } = {}) {
  let page;
  try { page = new URL(url); } catch { return null; }
  const unprotected = [];
  for (const tag of String(html ?? '').match(/<(?:script|link)\b[^>]*>/gi) ?? []) {
    const isScript = /^<script/i.test(tag);
    if (!isScript && !/\brel\s*=\s*["']?[^"'>]*\bstylesheet\b/i.test(tag)) continue;
    const ref = (isScript ? /\bsrc\s*=\s*["']?([^"'\s>]+)/i : /\bhref\s*=\s*["']?([^"'\s>]+)/i).exec(tag)?.[1];
    if (!ref || /\bintegrity\s*=/i.test(tag)) continue;
    let resource;
    try { resource = new URL(ref, page); } catch { continue; }
    if (resource.origin !== page.origin && /^https?:$/.test(resource.protocol)) unprotected.push(resource.href);
  }
  if (unprotected.length === 0) return null;
  return {
    check: 'web.headers.missing-sri',
    title: 'Third-party scripts or stylesheets load without Subresource Integrity',
    severity: 'low',
    confidence: 'confirmed',
    target: url,
    evidence: evidence ? [evidence] : [],
    description: `${unprotected.length} cross-origin resource(s) are loaded without an \`integrity\` hash, so the page runs whatever the third party serves.`,
    impact: 'If that CDN or host is compromised, the attacker\'s code runs on this page with full access to it.',
    remediation: 'Add `integrity="sha384-..."` and `crossorigin="anonymous"` to pinned third-party resources, or self-host them. Resources that change by design (analytics loaders) cannot be pinned; accept or self-host them.',
    observed: [{ key: 'resources', value: clip(unprotected.join(', ')) }],
    references: ['https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity'],
    cwe: ['CWE-353', 'CWE-829'],
    owasp: ['A08:2021']
  };
}

export function analyzeHeaders(headers, { scheme = 'https', url = '', evidence = null, metaCsp = null, metaReferrer = null } = {}) {
  const h = normalizeHeaders(headers);
  const schemeName = String(scheme ?? '').toLowerCase();
  const htmlLike = isHtmlLike(h);
  const evidenceIds = (Array.isArray(evidence) ? evidence : evidence ? [evidence] : []).filter(Boolean);
  const target = String(url ?? '');
  const findings = [];

  const push = (slug, severity, title, fields) => {
    findings.push({
      check: `web.headers.${slug}`,
      title,
      severity,
      confidence: 'confirmed',
      target,
      evidence: [...evidenceIds],
      ...fields
    });
  };

  /* ------------------------------------------------------------------ HSTS */
  const hstsRaw = headerValue(h, 'strict-transport-security');
  if (schemeName === 'https') {
    if (!hstsRaw) {
      push('missing-hsts', 'medium', 'Strict-Transport-Security (HSTS) header is missing', {
        description:
          'The HTTPS response does not set a Strict-Transport-Security header, so a browser may still ' +
          'follow a plain-HTTP link or typed URL to this host before the redirect happens. That window is ' +
          'what SSL-stripping proxies on hostile networks use.',
        impact:
          'Users can be silently downgraded to cleartext HTTP, exposing session cookies and credentials to ' +
          'an on-path attacker even though the site supports HTTPS.',
        remediation:
          'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response. ' +
          'Only add `preload` once the whole domain family is permanently HTTPS, then submit the domain to ' +
          'the HSTS preload list.',
        observed: [{ key: 'strict-transport-security', value: 'absent' }],
        references: [`${OWASP_SECURE_HEADERS}#strict-transport-security`],
        cwe: ['CWE-319'],
        owasp: ['A02:2021']
      });
    } else {
      const hsts = parseHsts(hstsRaw);
      if (hsts.maxAge == null || hsts.maxAge < HSTS_MIN_MAX_AGE) {
        push('weak-hsts-max-age', 'low', 'HSTS max-age is too short to be reliable', {
          description:
            'The Strict-Transport-Security header is present but its max-age is absent or below 180 days ' +
            `(observed: ${hsts.maxAge == null ? 'unparseable/absent' : `${hsts.maxAge} seconds`}).`,
          impact:
            'A short lifetime expires quickly; a user who visits the site rarely keeps almost no protection ' +
            'from downgrade attacks between visits.',
          remediation:
            'Raise the max-age to at least 15552000 (180 days) and preferably 31536000 (one year): ' +
            '`Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
          observed: [{ key: 'strict-transport-security', value: clip(hstsRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#strict-transport-security`],
          cwe: ['CWE-319'],
          owasp: ['A02:2021']
        });
      }
      if (!hsts.includeSubDomains) {
        push('hsts-missing-include-subdomains', 'low', 'HSTS policy does not cover subdomains', {
          description:
            'The Strict-Transport-Security header does not include the `includeSubDomains` directive, so the ' +
            'policy only protects the exact host that sent it.',
          impact:
            'HTTP-only subdomains (staging, legacy portals, mail front-ends) remain reachable over cleartext and ' +
            'can be used to steal cookies scoped to the parent domain.',
          remediation:
            'Add `includeSubDomains` to the header once every subdomain serves HTTPS: ' +
            '`Strict-Transport-Security: max-age=31536000; includeSubDomains`.',
          observed: [{ key: 'strict-transport-security', value: clip(hstsRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#strict-transport-security`],
          cwe: ['CWE-319'],
          owasp: ['A02:2021']
        });
      }
    }
  }

  /* ------------------------------------------------------------- CSP / XFO */
  const cspHeader = headerValue(h, 'content-security-policy');
  // A <meta> policy enforces fetch directives, so grade it, but it cannot carry frame-ancestors,
  // sandbox or reporting, so clickjacking protection still has to come from a header.
  const cspRaw = cspHeader ?? (htmlLike ? metaCsp : null);
  if (htmlLike) {
    if (!cspHeader && metaCsp) {
      push('csp-meta-only', 'info', 'Content-Security-Policy is set with a meta tag only', {
        description:
          'The page declares its CSP in a <meta http-equiv> tag instead of a response header. Browsers enforce ' +
          'its fetch directives, but ignore frame-ancestors, sandbox and report-uri/report-to in a meta policy.',
        impact: 'Framing control and violation reporting are unavailable; the policy also only starts applying once the tag is parsed.',
        remediation:
          'Where the host allows it, send the policy as a Content-Security-Policy response header. On hosts that ' +
          'cannot set headers (for example GitHub Pages), put the site behind a CDN that can, such as Cloudflare.',
        observed: [{ key: 'meta content-security-policy', value: clip(metaCsp) }],
        references: ['https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta#http-equiv'],
        cwe: ['CWE-693'],
        owasp: ['A05:2021']
      });
    }
    if (!cspRaw) {
      push('missing-csp', 'medium', 'Content-Security-Policy header is missing', {
        description:
          'HTML responses are served without a Content-Security-Policy. The browser therefore has no ' +
          'declared allow-list for scripts, styles, frames and other subresources.',
        impact:
          'Any HTML-injection or stored-XSS flaw in the application turns straight into script execution in ' +
          'the victim browser, with no second line of defence.',
        remediation:
          "Define a policy that starts strict and is rolled out in report-only mode first, e.g. " +
          "`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; " +
          "frame-ancestors 'none'; base-uri 'self'. Then iterate until violations are clean.",
        observed: [{ key: 'content-security-policy', value: 'absent' }],
        references: [`${OWASP_SECURE_HEADERS}#content-security-policy`, 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'],
        cwe: ['CWE-693'],
        owasp: ['A05:2021']
      });
    } else {
      const csp = parseCsp(cspRaw);
      const sourcesFor = (name) => csp.directives[name] ?? (name === 'default-src' ? [] : csp.directives['default-src'] ?? []);
      const unsafeInline = GRADEABLE_SOURCES.filter((directive) => sourcesFor(directive).includes("'unsafe-inline'"));
      const unsafeEval = GRADEABLE_SOURCES.filter((directive) => sourcesFor(directive).includes("'unsafe-eval'"));
      const wildcard = GRADEABLE_SOURCES.filter((directive) => sourcesFor(directive).includes('*'));
      if (unsafeInline.length > 0) {
        push('csp-unsafe-inline', 'medium', "Content-Security-Policy allows 'unsafe-inline'", {
          description:
            `The policy permits inline script/style execution (${unsafeInline.join(', ')}), which disables the ` +
            'main protection a CSP offers against injected scripts.',
          impact:
            'An XSS payload injected into an HTML or attribute context executes even with the policy enabled; ' +
            'the header gives a false sense of protection.',
          remediation:
            "Remove 'unsafe-inline' and use per-response nonces (`script-src 'nonce-<random>'`) or hashes. " +
            "For legacy inline handlers, refactor them into external files served under `script-src 'self'`.",
          observed: [{ key: 'directives', value: clip(unsafeInline.join(', ')) }, { key: 'content-security-policy', value: clip(cspRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#content-security-policy`],
          cwe: ['CWE-693', 'CWE-79'],
          owasp: ['A05:2021']
        });
      }
      if (unsafeEval.length > 0) {
        push('csp-unsafe-eval', 'medium', "Content-Security-Policy allows 'unsafe-eval'", {
          description: `The policy permits string-to-code evaluation (${unsafeEval.join(', ')}).`,
          impact:
            'Any server-side or client-side sink that reaches `eval`, `Function()` or similar gadget becomes ' +
            'a working XSS execution primitive instead of being blocked by the policy.',
          remediation:
            "Remove 'unsafe-eval' from the policy and replace `eval`/`new Function` usage with JSON parsing or " +
            'static code. If a framework needs it, isolate it behind a strict-dynamic policy.',
          observed: [{ key: 'directives', value: clip(unsafeEval.join(', ')) }, { key: 'content-security-policy', value: clip(cspRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#content-security-policy`],
          cwe: ['CWE-693', 'CWE-95'],
          owasp: ['A05:2021']
        });
      }
      if (wildcard.length > 0) {
        push('csp-wildcard-source', 'medium', 'Content-Security-Policy allows any source with `*`', {
          description: `A wildcard source is allowed for ${wildcard.join(', ')}, so scripts can be loaded from any host.`,
          impact:
            'A compromised or attacker-registered domain can serve code into the page, which largely defeats the ' +
            'purpose of the policy.',
          remediation:
            "Replace `*` with explicit origins (or 'self' plus a named CDN), then narrow each directive with " +
            "'strict-dynamic' or nonces as appropriate.",
          observed: [{ key: 'directives', value: clip(wildcard.join(', ')) }, { key: 'content-security-policy', value: clip(cspRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#content-security-policy`],
          cwe: ['CWE-693'],
          owasp: ['A05:2021']
        });
      }
      if (csp.directives['default-src'] == null) {
        push('csp-missing-default-src', 'low', "Content-Security-Policy has no default-src directive", {
          description:
            'The policy defines no `default-src` fallback, so directives that are not listed explicitly are ' +
            'unrestricted (for example font-src, connect-src, img-src or manifest-src).',
          impact:
            'Unlisted resource types can be loaded from any origin, widening the injection surface the policy ' +
            'was meant to close.',
          remediation:
            "Add `default-src 'self'` as the first directive of the policy, then override only the directives " +
            'that genuinely need other origins.',
          observed: [{ key: 'content-security-policy', value: clip(cspRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#content-security-policy`],
          cwe: ['CWE-693'],
          owasp: ['A05:2021']
        });
      }
      if (csp.directives['object-src'] == null) {
        push('csp-missing-object-src', 'low', "Content-Security-Policy has no object-src directive", {
          description:
            'The policy does not set `object-src`. Modern browsers fall back to `default-src`, but legacy ' +
            'Flash/Java plug-in content is not governed by the same fallback in every engine.',
          impact:
            'Legacy plug-in content could be embedded from an untrusted origin, a known CSP-bypass vector.',
          remediation: "Add `object-src 'none'` to the policy.",
          observed: [{ key: 'content-security-policy', value: clip(cspRaw) }],
          references: [`${OWASP_SECURE_HEADERS}#content-security-policy`],
          cwe: ['CWE-693'],
          owasp: ['A05:2021']
        });
      }
    }

    /* ------------------------------------------------------- clickjacking */
    // Only a header policy can carry frame-ancestors; a meta one is ignored for framing.
    const frameAncestors = cspHeader ? /\bframe-ancestors\b/i.test(cspHeader) : false;
    const xfo = headerValue(h, 'x-frame-options');
    if (!xfo && !frameAncestors) {
      push('missing-frame-protection', 'medium', 'Response is not protected against clickjacking', {
        description:
          'Neither an `X-Frame-Options` header nor a CSP `frame-ancestors` directive is set, so the page can ' +
          'be embedded in a frame on any site.',
        impact:
          'An attacker can overlay the application in an invisible frame and trick a signed-in user into ' +
          'clicking destructive or sensitive actions (clickjacking).',
        remediation:
          "Set `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` if framing is required). " +
          'Keep `X-Frame-Options: DENY` as a fallback for older browsers.',
        observed: [{ key: 'x-frame-options', value: 'absent' }, { key: 'csp-frame-ancestors', value: 'absent' }],
        references: [`${OWASP_SECURE_HEADERS}#x-frame-options`, 'https://owasp.org/www-community/attacks/Clickjacking'],
        cwe: ['CWE-1021'],
        owasp: ['A05:2021']
      });
    } else if (!xfo && frameAncestors) {
      // Covered by CSP frame-ancestors: acceptable, no finding.
    } else if (xfo && /allow-from/i.test(xfo)) {
      push('deprecated-x-frame-options', 'low', 'X-Frame-Options uses the obsolete ALLOW-FROM value', {
        description: 'The response sets `X-Frame-Options: ALLOW-FROM ...`, a value that modern browsers ignore.',
        impact: 'Frame protection is silently absent in current browsers, leaving the page clickjackable.',
        remediation:
          "Replace with `Content-Security-Policy: frame-ancestors 'self'` (CSP) and " +
          '`X-Frame-Options: SAMEORIGIN` for legacy clients.',
        observed: [{ key: 'x-frame-options', value: clip(xfo) }],
        references: [`${OWASP_SECURE_HEADERS}#x-frame-options`],
        cwe: ['CWE-1021'],
        owasp: ['A05:2021']
      });
    }

    /* ----------------------------------------------------- cross-origin isolation */
    if (!headerValue(h, 'cross-origin-opener-policy')) {
      push('missing-coop', 'low', 'Cross-Origin-Opener-Policy (COOP) header is missing', {
        description:
          'The response does not set `Cross-Origin-Opener-Policy`, so a cross-origin window that opens this ' +
          'document keeps a reference to it.',
        impact:
          'Cross-window scripting (XS-Leaks, Spectre-style side channels and window.opener abuse) is easier when ' +
          'the opener relationship is preserved.',
        remediation: "Set `Cross-Origin-Opener-Policy: same-origin` on HTML responses.",
        observed: [{ key: 'cross-origin-opener-policy', value: 'absent' }],
        references: [`${OWASP_SECURE_HEADERS}#cross-origin-opener-policy`],
        cwe: ['CWE-693'],
        owasp: ['A05:2021']
      });
    }
    if (!headerValue(h, 'cross-origin-embedder-policy')) {
      push('missing-coep', 'info', 'Cross-Origin-Embedder-Policy (COEP) header is missing', {
        description:
          'The response does not set `Cross-Origin-Embedder-Policy`. Without COEP the page is not ' +
          'cross-origin isolated, so powerful isolation-based mitigations are unavailable.',
        impact:
          'Some browser hardening features (high-precision timers, SharedArrayBuffer) are unavailable and ' +
          'cross-origin reads are less constrained.',
        remediation: "Set `Cross-Origin-Embedder-Policy: require-corp` once embedded resources opt in via CORP.",
        observed: [{ key: 'cross-origin-embedder-policy', value: 'absent' }],
        references: [`${OWASP_SECURE_HEADERS}#cross-origin-embedder-policy`],
        cwe: ['CWE-693'],
        owasp: ['A05:2021']
      });
    }
  }

  /* ------------------------------------------------------- MIME sniffing */
  if (!headerValue(h, 'x-content-type-options')) {
    push('missing-x-content-type-options', 'low', 'X-Content-Type-Options header is missing', {
      description:
        'The response does not set `X-Content-Type-Options: nosniff`, so some browsers will sniff a body and ' +
        'execute it as a type the server did not declare.',
      impact:
        'A user-uploaded file that is served back with a permissive content type can be interpreted as HTML ' +
        'or script, turning a file upload into stored XSS.',
      remediation: 'Set `X-Content-Type-Options: nosniff` on every response (it is cheap and safe to apply globally).',
      observed: [{ key: 'x-content-type-options', value: 'absent' }],
      references: [`${OWASP_SECURE_HEADERS}#x-content-type-options`],
      cwe: ['CWE-16'],
      owasp: ['A05:2021']
    });
  }

  /* ----------------------------------------------------------- referrer */
  // <meta name="referrer"> is honoured by browsers for the document, so it counts.
  const referrerPolicy = headerValue(h, 'referrer-policy') ?? (htmlLike ? metaReferrer : null);
  if (!referrerPolicy) {
    push('missing-referrer-policy', 'low', 'Referrer-Policy header is missing', {
      description:
        'The response does not set `Referrer-Policy`, so the browser default may leak full URLs to third ' +
        'parties through the `Referer` header.',
      impact:
        'URLs that contain tokens, reset links or internal paths are disclosed to external sites embedded in ' +
        'or linked from the application.',
      remediation: "Set `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`) globally.",
      observed: [{ key: 'referrer-policy', value: 'absent' }],
      references: [`${OWASP_SECURE_HEADERS}#referrer-policy`],
      cwe: ['CWE-200'],
      owasp: ['A05:2021']
    });
  } else if (/unsafe-url|no-referrer-when-downgrade/i.test(referrerPolicy)) {
    push('unsafe-referrer-policy', 'low', 'Referrer-Policy permits cross-origin URL leakage', {
      description: `The policy allows full URLs to be sent cross-origin (observed: \`${clip(referrerPolicy, 120)}\`).`,
      impact: 'Sensitive path or query-string data leaks to third-party sites via the Referer header.',
      remediation: "Use `Referrer-Policy: strict-origin-when-cross-origin` or stronger (`same-origin`, `no-referrer`).",
      observed: [{ key: 'referrer-policy', value: clip(referrerPolicy) }],
      references: [`${OWASP_SECURE_HEADERS}#referrer-policy`],
      cwe: ['CWE-200'],
      owasp: ['A05:2021']
    });
  }

  /* --------------------------------------------------------- permissions */
  if (!headerValue(h, 'permissions-policy') && !headerValue(h, 'feature-policy')) {
    push('missing-permissions-policy', 'info', 'Permissions-Policy header is missing', {
      description:
        'The response does not restrict powerful browser features. Without a policy, embedded third-party ' +
        'frames and compromised scripts can request camera, microphone, geolocation and similar access.',
      impact: 'Feature access is granted by default to any origin the page embeds, increasing blast radius.',
      remediation:
        "Set `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` and re-enable only " +
        'the features the application actually uses.',
      observed: [{ key: 'permissions-policy', value: 'absent' }],
      references: [`${OWASP_SECURE_HEADERS}#permissions-policy`],
      cwe: ['CWE-693'],
      owasp: ['A05:2021']
    });
  }

  /* -------------------------------------------------- cross-origin resource */
  if (!headerValue(h, 'cross-origin-resource-policy')) {
    push('missing-corp', 'info', 'Cross-Origin-Resource-Policy (CORP) header is missing', {
      description: 'The response does not declare a `Cross-Origin-Resource-Policy`, so it can be embedded cross-origin.',
      impact: 'Third-party pages can load the resource in no-cors mode, easing cross-origin data probing (e.g. XS-Leaks).',
      remediation: 'Set `Cross-Origin-Resource-Policy: same-origin` (or `same-site` where needed) on sensitive responses.',
      observed: [{ key: 'cross-origin-resource-policy', value: 'absent' }],
      references: [`${OWASP_SECURE_HEADERS}#cross-origin-resource-policy`],
      cwe: ['CWE-693'],
      owasp: ['A05:2021']
    });
  }

  /* ------------------------------------------------ information disclosure */
  const server = headerValue(h, 'server');
  const serverMatch = server ? SERVER_VERSION_RE.exec(server) : null;
  if (serverMatch) {
    push('server-version-disclosure', 'low', `Server header discloses the ${serverMatch[1]} version`, {
      description: `The response advertises the exact server software version (\`${clip(server, 120)}\`).`,
      impact:
        'An attacker can skip probing and directly target known CVEs for that version (nginx/Apache/IIS), ' +
        'and inventory the deployment stack without authentication.',
      remediation: serverRemediation(serverMatch[1]),
      observed: [{ key: 'server', value: clip(server) }],
      references: [`${OWASP_SECURE_HEADERS}#server`],
      cwe: ['CWE-200'],
      owasp: ['A05:2021']
    });
  }

  const poweredBy = headerValue(h, 'x-powered-by');
  if (poweredBy) {
    push('x-powered-by-disclosure', 'low', 'X-Powered-By header discloses the application stack', {
      description: `The response exposes the application framework via \`X-Powered-By: ${clip(poweredBy, 120)}\`.`,
      impact: 'The technology (and often its version) narrows the attack surface for an unauthenticated attacker.',
      remediation:
        'Remove the header at the framework/runtime layer: PHP `expose_php = Off`; Express `app.disable("x-powered-by")`; ' +
        'ASP.NET `<httpRuntime enableVersionHeader="false" />`; remove any custom `X-Powered-By` in IIS.',
      observed: [{ key: 'x-powered-by', value: clip(poweredBy) }],
      references: [`${OWASP_SECURE_HEADERS}#x-powered-by`],
      cwe: ['CWE-200'],
      owasp: ['A05:2021']
    });
  }

  const xssProtection = headerValue(h, 'x-xss-protection');
  if (xssProtection) {
    push('deprecated-x-xss-protection', 'info', 'Deprecated X-XSS-Protection header is set', {
      description:
        `The legacy \`X-XSS-Protection: ${clip(xssProtection, 80)}\` header is still sent. Modern browsers ignore ` +
        'it, and some historical values introduced new bugs (auditor bypasses).',
      impact: 'No real protection is provided, and outdated guidance may hide the absence of a modern CSP.',
      remediation:
        'Remove `X-XSS-Protection` and rely on a strict `Content-Security-Policy`. If a legacy client needs the ' +
        'header, `X-XSS-Protection: 0` is the only value that does not introduce risk.',
      observed: [{ key: 'x-xss-protection', value: clip(xssProtection) }],
      references: [`${OWASP_SECURE_HEADERS}#x-xss-protection`],
      cwe: ['CWE-16'],
      owasp: ['A05:2021']
    });
  }

  return { findings };
}

/** Concrete server-version remediation text, keyed by the product in the Server header. */
function serverRemediation(product) {
  const name = String(product ?? '').toLowerCase();
  if (name.includes('nginx')) return 'Set `server_tokens off;` in the nginx `http` block and reload. The header then emits `Server: nginx` only.';
  if (name.includes('apache')) return 'Set `ServerTokens Prod` and `ServerSignature Off` in the Apache configuration, then restart.';
  if (name.includes('iis') || name.includes('microsoft')) return 'Remove the `Server` version via a URL Rewrite outbound rule (or `Microsoft.Web.Administration`) so IIS emits a bare header.';
  if (name.includes('envoy')) return 'Set the Envoy `server_header_transformation` / `--suppress-envoy-headers` option so upstream versions are not exposed.';
  return 'Configure the web server or CDN to emit a bare `Server` header (or remove it entirely) so exact software versions are not advertised.';
}

/**
 * Turn the guarded response for a plain-HTTP origin into a finding when it failed to reach HTTPS.
 *
 * @param {{url?: string, status?: number, redirects?: object[], redirectsBlocked?: object|null}|null} response
 * @param {{origin?: string, evidence?: string|string[]|null}} [options]
 * @returns {object|null} finding, or null when the redirect chain ended on HTTPS (or could not be followed)
 */
export function analyzeHttpsRedirect(response, { origin = '', evidence = null } = {}) {
  if (!response?.url) return null;
  if (response.redirectsBlocked) return null;
  let final;
  try {
    final = new URL(response.url);
  } catch {
    return null;
  }
  if (final.protocol === 'https:') return null;
  const evidenceIds = (Array.isArray(evidence) ? evidence : evidence ? [evidence] : []).filter(Boolean);
  return {
    check: 'web.headers.no-https-redirect',
    title: 'Plain-HTTP origin does not redirect to HTTPS',
    severity: 'medium',
    confidence: 'confirmed',
    target: origin || response.url,
    evidence: [...evidenceIds],
    observed: [
      { key: 'requested', value: origin || response.url },
      { key: 'final-url', value: `${final.protocol}//${final.host}${final.pathname}` },
      { key: 'status', value: String(response.status ?? '') },
      { key: 'redirects', value: String((response.redirects ?? []).length) }
    ],
    description:
      'A cleartext request to this host was served directly instead of being redirected to the HTTPS origin. ' +
      'The site supports HTTPS but does not enforce it on the HTTP listener.',
    impact:
      'Users who follow or type a plain-HTTP URL send cookies and credentials in cleartext. An on-path attacker ' +
      'can read or modify that traffic before the user ever reaches the TLS endpoint.',
    remediation:
      'Redirect every HTTP request to the canonical HTTPS URL with a 301 (`return 301 https://$host$request_uri;` ' +
      'in nginx, `Redirect permanent / https://example/` in Apache), then enable HSTS with a long max-age.',
    references: [`${OWASP_SECURE_HEADERS}#strict-transport-security`, 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'],
    cwe: ['CWE-319'],
    owasp: ['A02:2021']
  };
}

/**
 * Build the plain-HTTP origin that corresponds to an HTTPS probe URL.
 * The default HTTPS port is dropped so the result points at the HTTP listener (:80).
 * @param {string} httpsUrl
 * @returns {string}
 */
export function httpOriginFor(httpsUrl) {
  try {
    const url = new URL(httpsUrl);
    const port = url.port && url.port !== '443' ? `:${url.port}` : '';
    return `http://${url.hostname}${port}`;
  } catch {
    return '';
  }
}

export default {
  id: 'web.headers',
  phase: 'web',
  title: 'HTTP security headers',
  description: 'Grades HSTS, CSP, clickjacking, MIME-sniffing, referrer, cross-origin and disclosure headers; verifies HTTPS enforcement.',
  defaults: { verifyHttpsRedirect: true },
  async run(ctx) {
    const probe = await ctx.openWebTarget();
    if (!probe) {
      ctx.logger.warn?.('no HTTP response from the web target; skipping header grading');
      return;
    }
    const evidenceId = probe.session?.evidence?.id ?? null;
    const { findings } = analyzeHeaders(probe.headers, {
      scheme: probe.scheme,
      url: probe.url,
      evidence: evidenceId,
      metaCsp: metaCspFromHtml(probe.text),
      metaReferrer: metaReferrerFromHtml(probe.text)
    });
    for (const finding of findings) await ctx.addFinding(finding);
    const sri = analyzeSubresourceIntegrity(probe.text, { url: probe.url, evidence: evidenceId });
    if (sri) await ctx.addFinding(sri);
    const headers = normalizeHeaders(probe.headers);
    await ctx.addAsset({
      type: 'endpoint',
      value: probe.url,
      attributes: { status: probe.status, server: headerValue(headers, 'server') ?? 'unknown', scheme: probe.scheme },
      state: 'tested'
    });

    if (probe.scheme === 'https' && ctx.options?.module?.verifyHttpsRedirect !== false) {
      const httpOrigin = httpOriginFor(probe.url);
      if (httpOrigin) {
        try {
          const plain = await ctx.guard.fetch(httpOrigin, { maxBytes: 8192, module: 'web.headers' });
          const redirectFinding = analyzeHttpsRedirect(plain, { origin: httpOrigin, evidence: plain.evidence?.id ?? null });
          if (redirectFinding) await ctx.addFinding(redirectFinding);
        } catch (error) {
          // The HTTP listener may be closed, filtered, or out of scope; that is not a finding we can prove.
          ctx.logger.debug?.(`HTTPS-redirect check for ${httpOrigin} skipped: ${error.message}`);
        }
      }
    }

    ctx.logger.info?.(`header grading produced ${findings.length} finding(s)`);
  }
};
