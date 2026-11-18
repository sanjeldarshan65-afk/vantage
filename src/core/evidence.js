import { appendJsonl, newId, nowIso, redactHeaders, redactUrl, readJsonl, sha256, truncate } from './util.js';

/**
 * Redact a `Set-Cookie` header value while keeping enough structure for analysis:
 * the cookie name and every attribute (Secure, HttpOnly, SameSite, Domain, Path, ...) stay
 * readable; only the secret value is replaced.
 * @param {string} raw
 * @returns {string}
 */
export function redactSetCookie(raw) {
  const text = String(raw ?? '');
  const parts = text.split(';');
  const head = parts.shift() ?? '';
  const equals = head.indexOf('=');
  const name = equals === -1 ? head.trim() : head.slice(0, equals).trim();
  const attributes = parts.map((part) => part.trim()).filter(Boolean);
  return [`${name}=<redacted>`, ...attributes].join('; ');
}

/** Build a redacted, hashable copy of an HTTP exchange for storage. */
function buildEvidenceRecord({ engagementId, runId, module, request, response, redirects = [], kind = 'http', extra = {} }) {
  const redactedRequest = {
    method: request.method,
    url: redactUrl(request.url),
    headers: redactHeaders(request.headers)
  };
  const body = Buffer.isBuffer(response.body) ? response.body : Buffer.from(String(response.body ?? ''), 'utf8');
  const preview = truncate(body.toString('utf8'), 4096);
  const redactedResponse = {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...redactHeaders(response.headers),
      ...(response.setCookie?.length
        ? { 'set-cookie': response.setCookie.map(redactSetCookie) }
        : {})
    },
    bodyPreview: preview,
    bodySha256: sha256(body),
    bodyBytes: body.length,
    truncated: Boolean(response.truncated),
    elapsedMs: response.elapsedMs ?? null,
    remoteAddress: response.remoteAddress ?? null
  };
  const hashBase = JSON.stringify({ request: redactedRequest, response: redactedResponse, redirects });
  return {
    id: newId('ev'),
    ts: nowIso(),
    engagementId,
    runId: runId ?? null,
    module: module ?? null,
    kind,
    request: redactedRequest,
    response: redactedResponse,
    redirects: redirects.map((hop) => ({ url: redactUrl(hop.url), status: hop.status })),
    sha256: sha256(hashBase),
    ...extra
  };
}

/**
 * Append-only evidence store. Every stored record is redacted (authorization / cookie values /
 * credential query parameters) and content-hashed so a report can prove it points at what was seen.
 */
export class EvidenceStore {
  /** @param {{file: string, engagementId: string}} opts */
  constructor({ file, engagementId }) {
    this.file = file;
    this.engagementId = engagementId;
    this.index = null;
    this.pending = [];
  }

  /** Lazily load the on-disk index; safe to call repeatedly. */
  async #ensureIndex() {
    if (this.index) return this.index;
    const rows = await readJsonl(this.file);
    this.index = new Map(rows.map((row) => [row.id, row]));
    return this.index;
  }

  /**
   * Store one HTTP exchange.
   * @returns {Promise<object>} the stored (redacted) evidence record
   */
  async save({ runId, module, request, response, redirects, kind = 'http', extra }) {
    const record = buildEvidenceRecord({
      engagementId: this.engagementId,
      runId,
      module,
      request,
      response,
      redirects,
      kind,
      extra
    });
    const index = await this.#ensureIndex();
    index.set(record.id, record);
    // Durability matters more than throughput here: a report must be able to resolve this id.
    await appendJsonl(this.file, record).catch(() => {});
    return record;
  }

  /** Store a DNS observation. */
  async saveDns({ runId, module, host, rrtype, records, elapsedMs, resolver }) {
    const request = { method: 'DNS', url: `dns://${host}/${rrtype}`, headers: {} };
    const response = {
      status: 0,
      statusText: 'NOERROR',
      headers: { 'x-vantage-resolver': resolver ?? 'system' },
      body: JSON.stringify(records),
      elapsedMs,
      remoteAddress: resolver ?? null
    };
    return this.save({ runId, module, request, response, kind: 'dns', extra: { dns: { host, rrtype, records } } });
  }

  async get(id) {
    const index = await this.#ensureIndex();
    return index.get(id) ?? null;
  }

  async list({ limit = 50, offset = 0, module, kind } = {}) {
    const index = await this.#ensureIndex();
    let rows = [...index.values()];
    if (module) rows = rows.filter((row) => row.module === module);
    if (kind) rows = rows.filter((row) => row.kind === kind);
    rows.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
    return rows.slice(offset, offset + limit);
  }

  async count() {
    const index = await this.#ensureIndex();
    return index.size;
  }

  async flush() {
    const pending = this.pending;
    this.pending = [];
    await Promise.all(pending);
  }
}

export { buildEvidenceRecord };
