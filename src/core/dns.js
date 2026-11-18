import { promises as dns } from 'node:dns';
import { NetworkError, ScopeError } from './errors.js';
import { sleep } from './util.js';

const DEFAULT_TIMEOUT = 4000;
const CACHE_TTL_MS = 300000;

/** Node's DNS callback API wrapped with a timeout so a dead resolver cannot hang a run. */
function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new NetworkError(`DNS ${label} timed out after ${ms}ms`, { code: 'ETIMEDOUT' })), ms).unref?.()
    )
  ]);
}

/**
 * Scope-checked, audited, cached DNS access.
 *
 * Modules must use this instead of `node:dns` directly; every query is checked against the
 * engagement scope and recorded in the audit trail.
 */
export class GuardDns {
  /** @param {import('./guard.js').ScopeGuard} guard */
  constructor(guard) {
    this.guard = guard;
    this.cache = new Map();
  }

  /** @param {string} key */
  #cached(key) {
    const hit = this.cache.get(key);
    if (!hit) return null;
    if (Date.now() - hit.at > CACHE_TTL_MS) {
      this.cache.delete(key);
      return null;
    }
    return hit.value;
  }

  /**
   * Run one audited DNS query.
   * @param {string} host
   * @param {string} rrtype A, AAAA, CNAME, MX, NS, TXT, SOA, PTR
   * @param {() => Promise<any>} query
   */
  async #run(host, rrtype, query) {
    const verdict = await this.guard.authorize({ host, kind: 'dns', rrtype });
    if (!verdict.allowed) {
      throw new ScopeError(`DNS query for ${host} refused: ${verdict.reason}`, { host, rrtype, reason: verdict.reason });
    }
    const cacheKey = `${rrtype}|${host}`;
    const cached = this.#cached(cacheKey);
    if (cached) return cached;

    const startedAt = process.hrtime.bigint();
    let records;
    try {
      records = await withTimeout(query(), this.guard.scope.limits.timeoutMs ?? DEFAULT_TIMEOUT, `${rrtype} ${host}`);
    } catch (error) {
      if (error instanceof NetworkError) {
        await this.guard.audit.record({
          action: `dns.${rrtype.toLowerCase()}`,
          host,
          target: host,
          allowed: true,
          reason: error.message,
          details: { error: error.code }
        });
        throw error;
      }
      // ENOTFOUND / ENODATA are normal answers, not failures.
      const code = error?.code ?? 'UNKNOWN';
      records = [];
      const result = { host, rrtype, records: [], error: code, elapsedMs: Number((process.hrtime.bigint() - startedAt) / 1_000_000n) };
      this.cache.set(cacheKey, { at: Date.now(), value: result });
      await this.guard.audit.record({
        action: `dns.${rrtype.toLowerCase()}`,
        host,
        target: host,
        allowed: true,
        reason: code,
        details: { rrtype, records: 0 }
      });
      return result;
    }

    const elapsedMs = Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
    const result = { host, rrtype, records: flattenRecords(rrtype, records), elapsedMs, error: null };
    this.cache.set(cacheKey, { at: Date.now(), value: result });
    const evidence = await this.guard.evidence.saveDns({
      runId: this.guard.runId,
      module: this.guard.currentModule,
      host,
      rrtype,
      records: result.records,
      elapsedMs
    });
    result.evidenceId = evidence.id;
    await this.guard.audit.record({
      action: `dns.${rrtype.toLowerCase()}`,
      host,
      target: host,
      allowed: true,
      reason: `${result.records.length} record(s)`,
      details: { rrtype, records: result.records.length, elapsedMs }
    });
    return result;
  }

  /** A/AAAA lookup with `all` semantics. */
  async lookup(host) {
    const verdict = await this.guard.authorize({ host, kind: 'dns', rrtype: 'LOOKUP' });
    if (!verdict.allowed) throw new ScopeError(`DNS lookup for ${host} refused: ${verdict.reason}`, { host, reason: verdict.reason });
    const cachedKey = `LOOKUP|${host}`;
    const cached = this.#cached(cachedKey);
    if (cached) return cached;
    let addresses = [];
    let error = null;
    try {
      addresses = await withTimeout(dns.lookup(host, { all: true, verbatim: true }), this.guard.scope.limits.timeoutMs ?? DEFAULT_TIMEOUT, `LOOKUP ${host}`);
    } catch (err) {
      error = err?.code ?? 'UNKNOWN';
    }
    const result = { host, addresses: addresses.map((entry) => entry.address), families: addresses.map((entry) => entry.family), error };
    this.cache.set(cachedKey, { at: Date.now(), value: result });
    await this.guard.audit.record({
      action: 'dns.lookup',
      host,
      target: host,
      allowed: true,
      reason: error ?? `${result.addresses.length} address(es)`,
      details: { addresses: result.addresses }
    });
    return result;
  }

  resolve(host, rrtype = 'A') {
    return this.#run(host, rrtype.toUpperCase(), () => dns.resolve(host, rrtype));
  }

  resolve4(host) {
    return this.#run(host, 'A', () => dns.resolve4(host, { ttl: true }));
  }

  resolve6(host) {
    return this.#run(host, 'AAAA', () => dns.resolve6(host, { ttl: true }));
  }

  resolveCname(host) {
    return this.#run(host, 'CNAME', () => dns.resolveCname(host));
  }

  resolveMx(host) {
    return this.#run(host, 'MX', () => dns.resolveMx(host));
  }

  resolveNs(host) {
    return this.#run(host, 'NS', () => dns.resolveNs(host));
  }

  resolveTxt(host) {
    return this.#run(host, 'TXT', () => dns.resolveTxt(host));
  }

  resolveSoa(host) {
    return this.#run(host, 'SOA', () => dns.resolveSoa(host));
  }

  reverse(ip) {
    return this.#run(ip, 'PTR', () => dns.reverse(ip));
  }

  /** One generic query for callers that iterate record types. */
  query(host, rrtype) {
    return this.#run(host, String(rrtype).toUpperCase(), () => dns.resolve(host, rrtype));
  }
}

/** Convert resolver output into flat, serializable records. */
export function flattenRecords(rrtype, records) {
  if (!Array.isArray(records)) return records ? [records] : [];
  switch (rrtype.toUpperCase()) {
    case 'TXT':
      return records.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)));
    case 'MX':
      return records.map((entry) => ({ exchange: entry.exchange, priority: entry.priority }));
    case 'A':
    case 'AAAA':
      return records.map((entry) => (typeof entry === 'string' ? entry : entry?.address ?? String(entry)));
    default:
      return records.map((entry) => entry);
  }
}

/** Resolve with a hard cap, used by the guard for scope matching. */
export async function resolveIps(host, timeoutMs = DEFAULT_TIMEOUT) {
  try {
    const entries = await withTimeout(dns.lookup(host, { all: true, verbatim: true }), timeoutMs, `LOOKUP ${host}`);
    return entries.map((entry) => entry.address);
  } catch {
    return [];
  }
}

export { sleep };
