import { isIP } from 'node:net';
import { ConfigError, NetworkError, ScopeError, VantageError } from './errors.js';
import { RateLimiter } from './rate.js';
import { requestOnce } from './http.js';
import { AuditLog } from './audit.js';
import { EvidenceStore } from './evidence.js';
import { GuardDns, resolveIps } from './dns.js';
import { tcpProbe as rawTcpProbe, tlsProbe as rawTlsProbe } from './tcp.js';
import { withinWindow, urlScopeInput } from './scope.js';
import { FILES, engagementFile } from './paths.js';

// TRACE is safe/idempotent per RFC 9110 (echo only) and is a standard method-audit probe.
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * The single choke point for every outbound action.
 *
 * Responsibilities: scope enforcement (including redirect hops and DNS-resolved IPs),
 * authorization-window check, rate/budget/concurrency limits, evidence capture, audit trail,
 * and throttle backoff.
 *
 * No module may make a network call without going through a guard instance.
 */
export class ScopeGuard {
  constructor({ engagement, scope, logger, runId = null, audit = null, evidence = null, limiter = null, module = null }) {
    if (!engagement || !scope) throw new ConfigError('ScopeGuard needs an engagement and a scope.');
    this.engagement = engagement;
    this.scope = scope;
    this.logger = logger;
    this.runId = runId;
    this.currentModule = module;
    this.audit = audit ?? new AuditLog({ file: engagementFile(engagement.id, FILES.audit), engagementId: engagement.id, runId });
    this.evidence = evidence ?? new EvidenceStore({ file: engagementFile(engagement.id, FILES.evidence), engagementId: engagement.id });
    this.limiter = limiter ?? new RateLimiter(scope.limits);
    this.dns = new GuardDns(this);
    this.denials = 0;
    this.requests = 0;
    this.redirectLimit = 5;
    this.userAgent = `Vantage/0.1 (authorized assessment; engagement ${engagement.id})`;
  }

  /** Bind a run / module so audit rows and evidence carry provenance. */
  setRun(runId, module = null) {
    this.runId = runId;
    this.audit.setRunId(runId);
    if (module !== null) this.currentModule = module;
  }

  setModule(moduleId) {
    this.currentModule = moduleId;
  }

  /** DNS-resolved addresses for a hostname, used to match IP/CIDR scope rules. */
  async #resolvedIps(host) {
    if (isIP(host)) return [];
    return resolveIps(host, Math.min(this.scope.limits.timeoutMs, 4000));
  }

  /**
   * Decide whether one target may be contacted, and audit the decision either way.
   * @param {{url?: string, host?: string, port?: number|null, scheme?: string|null, kind?: string, rrtype?: string}} target
   * @returns {Promise<{allowed: boolean, reason: string, rule: string|null, host: string, port: number|null}>}
   */
  async authorize(target = {}) {
    const parsed = target.url ? urlScopeInput(target.url) : { host: target.host, port: target.port ?? null, scheme: target.scheme ?? null };
    const host = parsed.host;
    const port = parsed.port ?? null;
    const scheme = parsed.scheme ?? null;
    const kind = target.kind ?? 'http';

    if (!host) {
      await this.audit.record({ action: `${kind}.deny`, target: target.url ?? '', allowed: false, reason: 'target has no host' });
      return { allowed: false, reason: 'target has no host', rule: null, host: '', port };
    }
    if (kind === 'http' && port == null) {
      await this.audit.record({ action: 'http.deny', target: target.url ?? host, host, allowed: false, reason: 'http target has no port' });
      return { allowed: false, reason: 'http target needs a port', rule: null, host, port };
    }

    let verdict = this.scope.matchHost(host, { port, scheme, resolvedIps: [] });
    if (!verdict.allowed && !isIP(host)) {
      const ips = await this.#resolvedIps(host);
      if (ips.length > 0) verdict = this.scope.matchHost(host, { port, scheme, resolvedIps: ips });
    }

    if (verdict.allowed) {
      const window = withinWindow(this.engagement);
      if (!window.allowed) verdict = { allowed: false, reason: window.reason, rule: null, host };
    }

    if (!verdict.allowed) this.denials += 1;
    await this.audit.record({
      action: `${kind}.${verdict.allowed ? 'allow' : 'deny'}`,
      target: target.url ?? `${host}${port != null ? `:${port}` : ''}`,
      host,
      allowed: verdict.allowed,
      reason: verdict.reason,
      details: { kind, port, scheme, rule: verdict.rule, rrtype: target.rrtype ?? null, module: this.currentModule }
    });
    if (verdict.allowed) {
      this.logger?.debug?.(`allow ${host}${port != null ? `:${port}` : ''} — ${verdict.reason}`);
    } else {
      this.logger?.scope?.(`deny ${host}${port != null ? `:${port}` : ''} — ${verdict.reason}`);
    }
    return { ...verdict, port };
  }

  /** Throwing variant of `authorize`. */
  async assert(target) {
    const verdict = await this.authorize(target);
    if (!verdict.allowed) {
      throw new ScopeError(`Scope refused ${target.url ?? target.host}: ${verdict.reason}`, { ...target, reason: verdict.reason });
    }
    return verdict;
  }

  /** Reject third-party services (RDAP, web search, ...) unless the engagement allows them. */
  async assertThirdParty(host, purpose = 'third-party request') {
    if (this.scope.allowThirdParty) return true;
    await this.audit.record({ action: 'thirdparty.deny', host, allowed: false, reason: `${purpose} blocked; allowThirdParty is false` });
    throw new ScopeError(`${purpose} to ${host} blocked: engagement does not allow third-party services.`, { host });
  }

  /**
   * Fetch a URL through the guard: per-hop scope checks, rate limits, evidence, redirect handling.
   *
   * @param {string} inputUrl
   * @param {{method?: string, headers?: Record<string,string>, body?: string|Buffer|null,
   *   followRedirects?: boolean, maxRedirects?: number, timeoutMs?: number, maxBytes?: number,
   *   signal?: AbortSignal, retryOnThrottle?: boolean, rejectUnauthorized?: boolean,
   *   module?: string, userAgent?: string}} [options]
   * @returns {Promise<object>} evidence-linked response
   */
  async fetch(inputUrl, options = {}) {
    const method = (options.method ?? 'GET').toUpperCase();
    if (!ALLOWED_METHODS.has(method) && !(method === 'POST' && options.body != null)) {
      throw new VantageError('http.method', `Method ${method} is not permitted by Vantage (read-only assessment).`);
    }
    const followRedirects = options.followRedirects !== false;
    const timeoutMs = options.timeoutMs ?? this.scope.limits.timeoutMs;
    const maxBytes = options.maxBytes ?? this.scope.limits.maxResponseBytes;
    const maxRedirects = options.maxRedirects ?? this.redirectLimit;
    const redirects = [];
    const moduleId = options.module ?? this.currentModule ?? null;
    let currentUrl = new URL(inputUrl);
    let currentMethod = method;
    let body = options.body ?? null;
    let response = null;
    let redirectsBlocked = null;
    let throttleRetries = 0;

    for (let hop = 0; hop <= maxRedirects; hop += 1) {
      const verdict = await this.authorize({ url: currentUrl.href, kind: 'http' });
      if (!verdict.allowed) {
        if (hop === 0) throw new ScopeError(`Scope refused ${currentUrl.href}: ${verdict.reason}`, { url: currentUrl.href, reason: verdict.reason });
        redirectsBlocked = { url: currentUrl.href, reason: verdict.reason };
        this.logger?.warn?.(`stopped following redirect to ${currentUrl.href} — ${verdict.reason}`);
        break;
      }

      await this.limiter.acquire(currentUrl.hostname, options.signal);
      this.requests += 1;
      try {
        response = await requestOnce(currentUrl.href, {
          method: currentMethod,
          headers: options.headers,
          body,
          timeoutMs,
          maxBytes,
          signal: options.signal,
          rejectUnauthorized: options.rejectUnauthorized,
          userAgent: options.userAgent ?? this.userAgent
        });
      } finally {
        this.limiter.release();
      }

      const status = response.status;
      if (REDIRECT_STATUSES.has(status) && response.location && followRedirects) {
        const next = new URL(response.location, currentUrl);
        redirects.push({ url: currentUrl.href, status, location: next.href });
        if (status === 303 || ((status === 301 || status === 302) && currentMethod === 'POST')) {
          currentMethod = 'GET';
          body = null;
        }
        currentUrl = next;
        continue;
      }

      // Throttle backoff: honour Retry-After once or twice, then report whatever came back.
      if ((status === 429 || status === 503) && options.retryOnThrottle !== false && throttleRetries < 2) {
        throttleRetries += 1;
        const retryAfter = Number(response.headers['retry-after']);
        const waitMs = Number.isFinite(retryAfter) && retryAfter > 0 ? Math.min(retryAfter * 1000, 10000) : 1000 * throttleRetries;
        this.logger?.debug?.(`${status} from ${currentUrl.hostname} — backing off ${waitMs}ms`);
        await this.limiter.backoff(waitMs, options.signal);
        hop -= 1; // retry the same hop
        continue;
      }
      break;
    }

    if (!response) throw new NetworkError(`No response for ${inputUrl}`, { url: inputUrl });

    const requestForEvidence = { method: currentMethod, url: currentUrl.href, headers: options.headers ?? {} };
    const evidence = await this.evidence.save({
      runId: this.runId,
      module: moduleId,
      request: requestForEvidence,
      response,
      redirects
    });

    return {
      url: currentUrl.href,
      status: response.status,
      statusText: response.statusText,
      ok: response.status >= 200 && response.status < 400,
      request: requestForEvidence,
      response,
      redirects,
      redirectsBlocked,
      evidence,
      get text() {
        return response.body.toString('utf8');
      },
      header(name) {
        const value = response.headers[String(name).toLowerCase()];
        if (Array.isArray(value)) return value.join(', ');
        return value ?? null;
      }
    };
  }

  /** HEAD request, falling back to GET when the server mishandles HEAD. */
  async head(url, options = {}) {
    try {
      return await this.fetch(url, { ...options, method: 'HEAD' });
    } catch (error) {
      if (error instanceof NetworkError) return this.fetch(url, options);
      throw error;
    }
  }

  /** Store a non-HTTP probe as evidence so findings can reference it. */
  async #probeEvidence({ kind, host, port, body, elapsedMs, meta }) {
    const text = Buffer.isBuffer(body) ? body : Buffer.from(String(body ?? ''), 'utf8');
    const evidence = await this.evidence.save({
      runId: this.runId,
      module: this.currentModule,
      kind,
      request: { method: kind.toUpperCase(), url: `${kind}://${host}:${port}`, headers: {} },
      response: {
        status: 0,
        statusText: 'OBSERVED',
        headers: {},
        body: text,
        elapsedMs,
        remoteAddress: host
      },
      extra: meta ? { probe: meta } : undefined
    });
    return evidence;
  }

  /**
   * Guarded TCP connect probe (port scan / banner grab). Read-only: connect, optional banner
   * read, close. Rate limited and audited like every other action.
   *
   * @param {string} host
   * @param {number} port
   * @param {{timeoutMs?: number, bannerBytes?: number, signal?: AbortSignal}} [options]
   * @returns {Promise<{host: string, port: number, open: boolean, elapsedMs: number, banner: string|null,
   *   error: string|null, evidenceId: string|null}>}
   */
  async tcpProbe(host, port, options = {}) {
    const verdict = await this.authorize({ host, port, kind: 'tcp' });
    if (!verdict.allowed) {
      throw new ScopeError(`TCP probe refused for ${host}:${port}: ${verdict.reason}`, { host, port, reason: verdict.reason });
    }
    await this.limiter.acquire(host, options.signal);
    let result;
    try {
      result = await rawTcpProbe(host, port, {
        timeoutMs: options.timeoutMs ?? Math.min(this.scope.limits.timeoutMs, 4000),
        bannerBytes: options.bannerBytes ?? 256
      });
    } finally {
      this.limiter.release();
    }
    this.requests += 1;
    const banner = result.banner ? result.banner.toString('utf8').replace(/\u0000/g, '') : null;
    let evidenceId = null;
    if (result.open) {
      const evidence = await this.#probeEvidence({ kind: 'tcp', host, port, body: banner ?? '', elapsedMs: result.elapsedMs, meta: { open: true } });
      evidenceId = evidence.id;
    }
    await this.audit.record({
      action: 'tcp.probe',
      target: `${host}:${port}`,
      host,
      allowed: true,
      reason: result.open ? 'open' : result.error ?? 'closed',
      details: { port, elapsedMs: result.elapsedMs, banner: banner ? banner.slice(0, 80) : null, module: this.currentModule }
    });
    return { host, port, open: result.open, elapsedMs: result.elapsedMs, banner, error: result.error, evidenceId };
  }

  /**
   * Guarded TLS handshake probe. Used to audit protocol versions, ciphers and certificate state.
   *
   * @param {string} host
   * @param {number} port
   * @param {{timeoutMs?: number, servername?: string, minVersion?: string, maxVersion?: string,
   *   signal?: AbortSignal}} [options]
   * @returns {Promise<{host: string, port: number, open: boolean, elapsedMs: number, tls: object|null,
   *   error: string|null, evidenceId: string|null}>}
   */
  async tlsProbe(host, port, options = {}) {
    const verdict = await this.authorize({ host, port, kind: 'tls' });
    if (!verdict.allowed) {
      throw new ScopeError(`TLS probe refused for ${host}:${port}: ${verdict.reason}`, { host, port, reason: verdict.reason });
    }
    await this.limiter.acquire(host, options.signal);
    let result;
    try {
      result = await rawTlsProbe(host, port, {
        timeoutMs: options.timeoutMs ?? this.scope.limits.timeoutMs,
        servername: options.servername ?? host,
        minVersion: options.minVersion,
        maxVersion: options.maxVersion
      });
    } finally {
      this.limiter.release();
    }
    this.requests += 1;
    const evidence = await this.#probeEvidence({
      kind: 'tls',
      host,
      port,
      body: JSON.stringify(result.tls ?? { error: result.error }, null, 2),
      elapsedMs: result.elapsedMs,
      meta: { handshake: result.open, error: result.error }
    });
    await this.audit.record({
      action: 'tls.probe',
      target: `${host}:${port}`,
      host,
      allowed: true,
      reason: result.open ? `handshake ${result.tls?.protocol ?? ''}` : result.error ?? 'failed',
      details: {
        port,
        protocol: result.tls?.protocol ?? null,
        minVersion: options.minVersion ?? null,
        maxVersion: options.maxVersion ?? null,
        module: this.currentModule
      }
    });
    return { host, port, open: result.open, elapsedMs: result.elapsedMs, tls: result.tls, error: result.error, evidenceId: evidence.id };
  }

  stats() {
    return {
      requests: this.requests,
      denials: this.denials,
      ...this.limiter.stats()
    };
  }
}

/** Build a guard for an engagement (CLI / engine entry point). */
export async function createGuard({ engagement, scope, logger, runId = null }) {
  return new ScopeGuard({ engagement, scope, logger, runId });
}
