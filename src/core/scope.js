import { isIP } from 'node:net';
import { ConfigError } from './errors.js';
import { DEFAULT_LIMITS } from './defaults.js';
import {
  normalizeHost,
  parseHostPort,
  parseCidr,
  cidrContains,
  ipToBigInt,
  defaultPort,
  clamp,
  nowIso
} from './util.js';
import { isValidEngagementId } from './paths.js';

/** Assessment depth. None of these enable exploitation; `full` only widens content discovery. */
export const MODES = Object.freeze(['passive', 'safe', 'full']);

const HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
const LABEL_COUNT = (host) => host.split('.').filter(Boolean).length;

/**
 * Parse one scope entry into a structured rule.
 * Accepted forms: hostname, `*.hostname`, IP literal, CIDR, or URL origin.
 * @param {string} raw
 * @returns {{type: string, describe: string, [key: string]: any}}
 */
export function parseScopeEntry(raw) {
  if (typeof raw !== 'string' || !raw.trim()) throw new ConfigError('Scope entries must be non-empty strings.');
  const text = raw.trim();

  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    let url;
    try {
      url = new URL(text);
    } catch {
      throw new ConfigError(`Invalid URL scope entry: ${text}`);
    }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      throw new ConfigError(`Only http(s) URL scope entries are supported: ${text}`);
    }
    if (url.username || url.password) throw new ConfigError(`Scope URLs must not embed credentials: ${text}`);
    const scheme = url.protocol.slice(0, -1);
    const host = normalizeHost(url.hostname);
    if (!host) throw new ConfigError(`Invalid URL host in scope entry: ${text}`);
    const port = url.port ? Number(url.port) : defaultPort(scheme);
    return { type: 'url', scheme, host, port, describe: `${scheme}://${host}:${port}` };
  }

  if (text.includes('/')) {
    const range = parseCidr(text);
    if (!range) throw new ConfigError(`Invalid CIDR scope entry: ${text}`);
    const minimumBits = range.total === 32 ? 8 : 16;
    if (range.bits < minimumBits) {
      throw new ConfigError(
        `CIDR scope entry ${text} is too broad (/${range.bits}). Narrow it to at least /${minimumBits}; ` +
          'an engagement should name the assets it covers, not the internet.'
      );
    }
    return { type: 'cidr', family: range.family, bits: range.bits, network: range.network, last: range.last, total: range.total, describe: range.cidr };
  }

  if (isIP(text)) {
    return { type: 'ip', value: normalizeHost(text), big: ipToBigInt(text), describe: normalizeHost(text) };
  }

  if (text.startsWith('*.')) {
    const suffix = normalizeHost(text.slice(2));
    if (!HOSTNAME_RE.test(suffix) || LABEL_COUNT(suffix) < 2) {
      throw new ConfigError(`Wildcard scope entry ${text} must be *.name.tld (subdomains only, at least two labels).`);
    }
    return { type: 'wildcard', suffix, describe: `*.${suffix}` };
  }

  const host = normalizeHost(text);
  if (!HOSTNAME_RE.test(host)) throw new ConfigError(`Invalid hostname scope entry: ${text}`);
  return { type: 'host', value: host, describe: host };
}

function normalizePortList(value, field) {
  if (value == null) return [];
  if (!Array.isArray(value)) throw new ConfigError(`${field} must be an array of port numbers.`);
  const ports = [];
  for (const raw of value) {
    const port = Number(raw);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new ConfigError(`${field} contains an invalid port: ${raw}`);
    ports.push(port);
  }
  return [...new Set(ports)];
}

/**
 * An engagement scope: what may be tested, and how fast.
 *
 * `exclude` always wins over `targets`. Hostnames are also matched by their resolved IPs against
 * IP/CIDR rules, so an IP-range scope cannot be bypassed by using a name.
 */
export class Scope {
  /**
   * @param {{targets: string[], exclude?: string[], ports?: object, limits?: object, mode?: string}} spec
   */
  constructor(spec = {}) {
    const targets = Array.isArray(spec.targets) ? spec.targets : spec.targets ? [spec.targets] : [];
    if (targets.length === 0) {
      throw new ConfigError('Scope must list at least one target. Refusing to run an unscoped assessment.');
    }
    this.targets = targets.map(parseScopeEntry);
    this.exclude = (Array.isArray(spec.exclude) ? spec.exclude : []).map(parseScopeEntry);
    this.ports = {
      include: normalizePortList(spec.ports?.include, 'ports.include'),
      exclude: normalizePortList(spec.ports?.exclude, 'ports.exclude')
    };
    this.mode = MODES.includes(spec.mode) ? spec.mode : 'safe';
    const rawLimits = spec.limits ?? {};
    this.limits = {
      requestsPerSecond: clamp(Number(rawLimits.requestsPerSecond ?? DEFAULT_LIMITS.requestsPerSecond), 0.2, 50),
      perHostRequestsPerSecond: clamp(Number(rawLimits.perHostRequestsPerSecond ?? DEFAULT_LIMITS.perHostRequestsPerSecond), 0.2, 25),
      concurrency: Math.round(clamp(Number(rawLimits.concurrency ?? DEFAULT_LIMITS.concurrency), 1, 16)),
      maxRequests: Math.round(clamp(Number(rawLimits.maxRequests ?? DEFAULT_LIMITS.maxRequests), 1, 100000)),
      timeoutMs: Math.round(clamp(Number(rawLimits.timeoutMs ?? DEFAULT_LIMITS.timeoutMs), 500, 60000)),
      maxResponseBytes: Math.round(clamp(Number(rawLimits.maxResponseBytes ?? DEFAULT_LIMITS.maxResponseBytes), 1024, 5 * 1024 * 1024)),
      maxEvidenceBytes: Math.round(clamp(Number(rawLimits.maxEvidenceBytes ?? DEFAULT_LIMITS.maxEvidenceBytes), 256, 65536))
    };
    this.allowThirdParty = Boolean(spec.allowThirdParty);
  }

  /** Port allowed by the include/exclude lists alone (host check happens separately). */
  allowedPort(port) {
    if (port == null) return { allowed: true, reason: 'no port restriction for this action' };
    const n = Number(port);
    if (!Number.isInteger(n) || n < 1 || n > 65535) return { allowed: false, reason: `invalid port ${port}` };
    if (this.ports.exclude.includes(n)) return { allowed: false, reason: `port ${n} is explicitly excluded` };
    if (this.ports.include.length > 0 && !this.ports.include.includes(n)) {
      return { allowed: false, reason: `port ${n} is not in the allowed port list (${this.ports.include.join(', ')})` };
    }
    return { allowed: true, reason: `port ${n} is allowed` };
  }

  /** Does one rule match this host/port/scheme? */
  #ruleMatches(rule, host, { port, scheme, resolvedIps }) {
    switch (rule.type) {
      case 'host':
        return rule.value === host;
      case 'wildcard':
        return host.endsWith(`.${rule.suffix}`);
      case 'ip':
        if (isIP(host)) return ipToBigInt(host) === rule.big;
        return false;
      case 'cidr': {
        if (isIP(host)) return cidrContains(rule, host);
        return resolvedIps.some((ip) => cidrContains(rule, ip));
      }
      case 'url': {
        if (rule.host !== host) return false;
        if (scheme && rule.scheme !== scheme) return false;
        if (port != null && rule.port !== port) return false;
        return true;
      }
      default:
        return false;
    }
  }

  #firstMatch(rules, host, opts) {
    for (const rule of rules) {
      if (this.#ruleMatches(rule, host, opts)) return rule;
    }
    return null;
  }

  /**
   * Decide whether a host may be contacted.
   * @param {string} rawHost hostname or IP literal
   * @param {{port?: number|null, scheme?: string|null, resolvedIps?: string[]}} [opts]
   * @returns {{allowed: boolean, reason: string, rule: string|null, host: string}}
   */
  matchHost(rawHost, opts = {}) {
    const host = normalizeHost(rawHost);
    const resolvedIps = Array.isArray(opts.resolvedIps) ? opts.resolvedIps.filter(Boolean) : [];
    const ctx = { port: opts.port ?? null, scheme: opts.scheme ?? null, resolvedIps };
    if (!host) return { allowed: false, reason: 'empty host', rule: null, host };

    const denied = this.#firstMatch(this.exclude, host, ctx);
    if (denied) return { allowed: false, reason: `excluded by rule ${denied.describe}`, rule: denied.describe, host };

    const portVerdict = this.allowedPort(ctx.port);
    if (!portVerdict.allowed) return { allowed: false, reason: portVerdict.reason, rule: null, host };

    const matched = this.#firstMatch(this.targets, host, ctx);
    if (matched) return { allowed: true, reason: `in scope via ${matched.describe}`, rule: matched.describe, host };
    return { allowed: false, reason: 'host is not covered by any in-scope rule', rule: null, host };
  }

  /** Human-readable scope summary (used by reports and `scope check`). */
  describe() {
    return {
      mode: this.mode,
      targets: this.targets.map((rule) => rule.describe),
      exclude: this.exclude.map((rule) => rule.describe),
      ports: this.ports,
      limits: this.limits,
      allowThirdParty: this.allowThirdParty
    };
  }

  toJSON() {
    return {
      targets: this.targets.map((rule) => rule.describe),
      exclude: this.exclude.map((rule) => rule.describe),
      ports: this.ports,
      limits: this.limits,
      allowThirdParty: this.allowThirdParty,
      mode: this.mode
    };
  }
}

/**
 * Validate and normalize an engagement document.
 * @param {object} raw parsed `engagement.json`
 * @returns {{engagement: object, scope: Scope, options: object}}
 */
export function normalizeEngagement(raw) {
  if (!raw || typeof raw !== 'object') throw new ConfigError('engagement.json must contain an object.');
  const meta = raw.engagement ?? raw;
  const id = String(meta.id ?? '');
  if (!isValidEngagementId(id)) {
    throw new ConfigError(`Engagement id "${id}" is invalid: use lowercase letters, digits, dot, dash or underscore.`);
  }
  const name = typeof meta.name === 'string' && meta.name.trim() ? meta.name.trim() : id;
  const authorizationRef = typeof meta.authorizationRef === 'string' ? meta.authorizationRef.trim() : '';
  if (!authorizationRef) {
    throw new ConfigError(
      `Engagement "${id}" has no authorizationRef. VANTAGE only tests assets you are authorized to test; ` +
        'record the written authorization (SOW / engagement letter / bug-bounty scope) in engagement.authorizationRef.'
    );
  }
  const mode = MODES.includes(meta.mode) ? meta.mode : 'safe';
  const startsAt = meta.startsAt ? new Date(meta.startsAt) : null;
  const endsAt = meta.endsAt ? new Date(meta.endsAt) : null;
  if (startsAt && Number.isNaN(startsAt.getTime())) throw new ConfigError(`Invalid engagement.startsAt: ${meta.startsAt}`);
  if (endsAt && Number.isNaN(endsAt.getTime())) throw new ConfigError(`Invalid engagement.endsAt: ${meta.endsAt}`);
  if (startsAt && endsAt && endsAt < startsAt) throw new ConfigError('engagement.endsAt is before engagement.startsAt.');

  const engagement = {
    id,
    name,
    client: typeof meta.client === 'string' ? meta.client : '',
    authorizedBy: typeof meta.authorizedBy === 'string' ? meta.authorizedBy : '',
    authorizationRef,
    startsAt: startsAt ? startsAt.toISOString() : null,
    endsAt: endsAt ? endsAt.toISOString() : null,
    mode,
    notes: typeof meta.notes === 'string' ? meta.notes : '',
    createdAt: meta.createdAt ?? nowIso()
  };

  const scopeSpec = raw.scope ?? {};
  const scope = new Scope({
    targets: scopeSpec.targets,
    exclude: scopeSpec.exclude,
    ports: scopeSpec.ports,
    limits: scopeSpec.limits,
    mode,
    allowThirdParty: scopeSpec.allowThirdParty
  });

  const options = raw.options && typeof raw.options === 'object' ? { ...raw.options } : {};
  return { engagement, scope, options };
}

/**
 * True when the engagement authorization window covers `at`.
 * @returns {{allowed: boolean, reason: string}}
 */
export function withinWindow(engagement, at = new Date()) {
  const ts = at.getTime();
  if (engagement.startsAt && ts < new Date(engagement.startsAt).getTime()) {
    return { allowed: false, reason: `engagement authorization starts ${engagement.startsAt}` };
  }
  if (engagement.endsAt && ts > new Date(engagement.endsAt).getTime()) {
    return { allowed: false, reason: `engagement authorization ended ${engagement.endsAt}` };
  }
  return { allowed: true, reason: 'within authorization window' };
}

/** Build a ready-to-edit engagement document. */
export function createEngagementTemplate({ id, name, targets, client = '', authorizedBy = '', authorizationRef, startsAt, endsAt, mode = 'safe' }) {
  const targetList = (Array.isArray(targets) ? targets : [targets]).filter(Boolean);
  if (targetList.length === 0) throw new ConfigError('init needs at least one in-scope target (--target).');
  const scope = new Scope({ targets: targetList, mode });
  return {
    engagement: {
      id,
      name: name ?? id,
      client,
      authorizedBy,
      authorizationRef: authorizationRef ?? 'REPLACE WITH YOUR WRITTEN AUTHORIZATION REFERENCE',
      startsAt: startsAt ?? nowIso(),
      endsAt: endsAt ?? null,
      mode,
      notes: ''
    },
    scope: {
      targets: scope.targets.map((rule) => rule.describe),
      exclude: [],
      ports: { include: [], exclude: [] },
      limits: { ...scope.limits },
      allowThirdParty: false
    },
    options: {
      ports: 'top100',
      paths: 'safe',
      subdomains: 'short'
    }
  };
}

/** Convenience: does this engagement host match (without throwing)? */
export function scopeAllowsHost(scope, host, opts) {
  try {
    return scope.matchHost(host, opts).allowed;
  } catch {
    return false;
  }
}

/** Parse a URL into the guard's decision input. */
export function urlScopeInput(url) {
  const { host, port, scheme } = parseHostPort(url);
  return { host, port, scheme };
}
