import { createHash, timingSafeEqual } from 'node:crypto';
import { EngagementStore } from '../src/core/store.js';
import { SEVERITIES, STATUSES, summarizeFindings } from '../src/core/findings.js';
import { ConfigError, NotFoundError } from '../src/core/errors.js';
import { isValidEngagementId } from '../src/core/paths.js';
import { handleEvents } from './sse.js';

/** JSON responses are never cached: the dashboard always reflects disk state. */
export const API_HEADERS = Object.freeze({
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store'
});

const MAX_BODY_BYTES = 64 * 1024;
const MAX_NOTE_CHARS = 2000;
const REPORT_FORMATS = Object.freeze({
  json: { type: 'application/json; charset=utf-8', ext: 'json' },
  md: { type: 'text/markdown; charset=utf-8', ext: 'md' },
  html: { type: 'text/html; charset=utf-8', ext: 'html' },
  sarif: { type: 'application/sarif+json; charset=utf-8', ext: 'sarif' }
});

/** An error carrying the HTTP status and stable code the API should return. */
export class HttpError extends Error {
  /**
   * @param {number} status HTTP status code
   * @param {string} code stable machine-readable code
   * @param {string} message human readable message
   */
  constructor(status, code, message) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
  }
}

/**
 * Constant-time token comparison. Both values are hashed first so the comparison length never
 * depends on the supplied token length.
 * @param {string} expected
 * @param {unknown} provided
 * @returns {boolean}
 */
export function tokensMatch(expected, provided) {
  const providedText = Array.isArray(provided) ? provided[0] : provided;
  if (typeof expected !== 'string' || expected.length === 0) return false;
  if (typeof providedText !== 'string' || providedText.length === 0) return false;
  const digest = (value) => createHash('sha256').update(value, 'utf8').digest();
  return timingSafeEqual(digest(expected), digest(providedText));
}

/** Write a JSON response. */
export function sendJson(res, status, body, extraHeaders = {}) {
  if (res.headersSent || res.writableEnded) return;
  res.writeHead(status, { ...API_HEADERS, ...extraHeaders });
  res.end(JSON.stringify(body));
}

function emptySeverityCounts() {
  return Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
}

/**
 * Compact run representation used by list endpoints and the runs table.
 * @param {object} run
 */
export function summarizeRun(run) {
  const stats = run?.stats ?? {};
  return {
    id: run?.id ?? null,
    startedAt: run?.startedAt ?? null,
    endedAt: run?.endedAt ?? null,
    elapsedMs: run?.elapsedMs ?? null,
    status: run?.status ?? 'unknown',
    mode: run?.mode ?? null,
    target: typeof run?.target === 'string' ? run.target : run?.target?.url ?? run?.target?.host ?? null,
    phases: Array.isArray(run?.phases) ? run.phases : [],
    modules: Array.isArray(run?.modules) ? run.modules.length : 0,
    stats: {
      modules: stats.modules ?? (Array.isArray(run?.modules) ? run.modules.length : 0),
      findings: stats.findings ?? 0,
      assets: stats.assets ?? 0,
      requests: stats.requests ?? 0,
      denials: stats.denials ?? 0,
      evidence: stats.evidence ?? 0
    },
    summary: run?.summary
      ? {
          total: run.summary.total ?? 0,
          open: run.summary.open ?? 0,
          bySeverity: run.summary.bySeverity ?? emptySeverityCounts(),
          riskScore: run.summary.riskScore ?? 0
        }
      : null
  };
}

/**
 * Read and parse a small JSON request body.
 * @param {import('node:http').IncomingMessage} req
 * @param {number} [limit]
 */
export async function readJsonBody(req, limit = MAX_BODY_BYTES) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) {
      req.resume();
      throw new HttpError(413, 'body.too_large', `Request body exceeds ${limit} bytes.`);
    }
    chunks.push(chunk);
  }
  if (size === 0) return {};
  let parsed;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'body.invalid_json', 'Request body must be valid JSON.');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new HttpError(400, 'body.invalid_json', 'Request body must be a JSON object.');
  }
  return parsed;
}

function methodNotAllowed(res, allowed) {
  sendJson(res, 405, { error: `Method not allowed; use ${allowed.join(', ')}.`, code: 'method.not_allowed' }, { Allow: allowed.join(', ') });
}

/**
 * Build the API request handler bound to one engagements root and server token.
 *
 * Engagements are opened from disk per request: the dashboard must reflect state written by a
 * separate CLI process, so caching a live store in the server would serve stale findings.
 *
 * @param {{engagementsRoot: string, token: string, logger?: object, bus?: object}} opts
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse, url: URL) => Promise<void>}
 */
export function createApiHandler({ engagementsRoot, token, logger = null, bus = null }) {
  /**
   * Open an engagement, translating lookup failures into HTTP errors.
   * @param {string} id
   */
  async function openEngagement(id) {
    if (!isValidEngagementId(id)) throw new HttpError(404, 'not_found', 'Engagement not found.');
    try {
      return await EngagementStore.open(id, { engagementsRoot });
    } catch (error) {
      if (error instanceof NotFoundError) throw new HttpError(404, 'not_found', `Engagement "${id}" not found.`);
      throw error;
    }
  }

  /** Reject a mutating request unless the token matches. */
  function requireToken(req) {
    if (!tokensMatch(token, req.headers['x-vantage-token'])) {
      throw new HttpError(401, 'auth.invalid_token', 'A valid x-vantage-token header is required for this request.');
    }
  }

  async function health(_req, res) {
    sendJson(res, 200, {
      ok: true,
      name: 'vantage',
      ts: new Date().toISOString(),
      node: process.version,
      uptimeMs: Math.round(process.uptime() * 1000),
      live: bus?.status ? bus.status() : null
    });
  }

  async function listEngagements(_req, res) {
    const summaries = await EngagementStore.list({ engagementsRoot });
    const engagements = [];
    for (const summary of summaries) {
      let counts = {
        findings: summary.findings,
        open: 0,
        bySeverity: emptySeverityCounts(),
        byStatus: {},
        assets: summary.assets,
        tested: 0,
        runs: summary.runs,
        evidence: 0
      };
      let coverage = { total: summary.assets, tested: 0, untested: summary.assets, percentTested: 0, byType: {} };
      let lastRun = null;
      try {
        const store = await EngagementStore.open(summary.id, { engagementsRoot });
        const findings = store.listFindings();
        const findingSummary = summarizeFindings(findings);
        coverage = store.coverage();
        const runs = store.listRuns();
        lastRun = runs.length > 0 ? summarizeRun(runs[0]) : null;
        counts = {
          findings: findingSummary.total,
          open: findingSummary.open,
          bySeverity: findingSummary.bySeverity,
          byStatus: findingSummary.byStatus,
          highest: findingSummary.highest,
          riskScore: findingSummary.riskScore,
          assets: coverage.total,
          tested: coverage.tested,
          runs: runs.length,
          evidence: await store.evidence.count()
        };
      } catch (error) {
        logger?.debug?.(`could not read engagement ${summary.id}: ${error.message}`);
      }
      engagements.push({
        id: summary.id,
        name: summary.name,
        client: summary.client,
        mode: summary.mode,
        authorizationRef: summary.authorizationRef,
        endsAt: summary.endsAt,
        counts,
        coverage,
        lastRun,
        lastRunAt: summary.lastRunAt
      });
    }
    sendJson(res, 200, engagements);
  }

  async function engagementDetail(_req, res, id) {
    const store = await openEngagement(id);
    const snapshot = await store.snapshot({ activityLimit: 50, includeAudit: true });
    const runs = store.listRuns().map(summarizeRun);
    const requests = runs.reduce((total, run) => total + (run.stats.requests ?? 0), 0);
    const denials = runs.reduce((total, run) => total + (run.stats.denials ?? 0), 0);
    sendJson(res, 200, {
      generatedAt: snapshot.generatedAt,
      engagement: snapshot.engagement,
      scope: snapshot.scope,
      options: snapshot.options,
      summary: snapshot.summary,
      coverage: snapshot.coverage,
      activity: snapshot.activity,
      audit: snapshot.audit,
      counts: {
        findings: snapshot.summary.total,
        open: snapshot.summary.open,
        bySeverity: snapshot.summary.bySeverity,
        byStatus: snapshot.summary.byStatus,
        highest: snapshot.summary.highest,
        riskScore: snapshot.summary.riskScore,
        assets: snapshot.coverage.total,
        tested: snapshot.coverage.tested,
        untested: snapshot.coverage.untested,
        coveragePercent: snapshot.coverage.percentTested,
        evidence: snapshot.evidenceCount,
        runs: runs.length,
        requests,
        denials
      },
      runs
    });
  }

  async function listFindings(_req, res, id, url) {
    const store = await openEngagement(id);
    const filters = {
      severity: url.searchParams.get('severity') || undefined,
      status: url.searchParams.get('status') || undefined,
      check: url.searchParams.get('check') || undefined,
      search: url.searchParams.get('search') || undefined,
      sort: url.searchParams.get('sort') || 'severity'
    };
    const findings = store.listFindings(filters);
    sendJson(res, 200, {
      findings,
      count: findings.length,
      total: store.findings.length,
      filters
    });
  }

  async function findingDetail(_req, res, id, findingId) {
    const store = await openEngagement(id);
    const finding = store.getFinding(findingId);
    if (!finding) throw new HttpError(404, 'not_found', `Finding "${findingId}" not found.`);
    sendJson(res, 200, finding);
  }

  async function patchFinding(req, res, id, findingId) {
    requireToken(req);
    const store = await openEngagement(id);
    const body = await readJsonBody(req);
    const status = body.status === undefined || body.status === null ? undefined : String(body.status);
    const note = body.note === undefined || body.note === null ? '' : body.note;
    if (status !== undefined && !STATUSES.includes(status)) {
      throw new HttpError(400, 'finding.invalid_status', `Unknown finding status "${status}". Expected one of: ${STATUSES.join(', ')}.`);
    }
    if (typeof note !== 'string') throw new HttpError(400, 'request.invalid', 'The note field must be a string.');
    if (note.length > MAX_NOTE_CHARS) throw new HttpError(400, 'request.invalid', `The note field must be ${MAX_NOTE_CHARS} characters or fewer.`);
    if (status === undefined && note.trim() === '') {
      throw new HttpError(400, 'request.invalid', 'Provide a status and/or a note.');
    }
    const finding = await store.updateFinding(findingId, { status, note: note.trim(), actor: 'operator' });
    if (!finding) throw new HttpError(404, 'not_found', `Finding "${findingId}" not found.`);
    await store.flush();
    bus?.publish?.({ type: 'finding:updated', engagementId: id, finding });
    logger?.debug?.(`finding ${findingId} updated (${status ?? 'note'})`);
    sendJson(res, 200, { finding });
  }

  async function listAssets(_req, res, id, url) {
    const store = await openEngagement(id);
    const assets = store.listAssets({
      type: url.searchParams.get('type') || undefined,
      state: url.searchParams.get('state') || undefined
    });
    sendJson(res, 200, { assets, coverage: store.coverage() });
  }

  async function listRuns(_req, res, id) {
    const store = await openEngagement(id);
    sendJson(res, 200, store.listRuns().map(summarizeRun));
  }

  async function runDetail(_req, res, id, runId) {
    const store = await openEngagement(id);
    const run = store.getRun(runId);
    if (!run) throw new HttpError(404, 'not_found', `Run "${runId}" not found.`);
    sendJson(res, 200, run);
  }

  async function listEvidence(_req, res, id, url) {
    const store = await openEngagement(id);
    const limit = clampInt(url.searchParams.get('limit'), 1, 200, 50);
    const offset = clampInt(url.searchParams.get('offset'), 0, 1_000_000, 0);
    const evidence = await store.evidence.list({
      limit,
      offset,
      module: url.searchParams.get('module') || undefined,
      kind: url.searchParams.get('kind') || undefined
    });
    sendJson(res, 200, { evidence, total: await store.evidence.count(), limit, offset });
  }

  async function evidenceDetail(_req, res, id, evidenceId) {
    const store = await openEngagement(id);
    const record = await store.evidence.get(evidenceId);
    if (!record) throw new HttpError(404, 'not_found', `Evidence "${evidenceId}" not found.`);
    sendJson(res, 200, record);
  }

  async function report(req, res, id, url) {
    const format = String(url.searchParams.get('format') ?? 'json').toLowerCase();
    const spec = REPORT_FORMATS[format];
    if (!spec) {
      throw new HttpError(400, 'report.invalid_format', `Unsupported format "${format}". Use one of: ${Object.keys(REPORT_FORMATS).join(', ')}.`);
    }
    const store = await openEngagement(id);
    let reportModule;
    try {
      reportModule = await import('../src/report/index.js');
    } catch (error) {
      logger?.debug?.(`report module unavailable: ${error.message}`);
      sendJson(res, 501, { error: 'report module not available', code: 'report.unavailable' });
      return;
    }
    if (typeof reportModule.buildReport !== 'function') {
      sendJson(res, 501, { error: 'report module not available', code: 'report.unavailable' });
      return;
    }
    let built;
    try {
      built = await reportModule.buildReport(store);
    } catch (storeError) {
      // The frozen interface passes a live store; accepting a plain snapshot too keeps the
      // endpoint working if the report module implements the narrower pure signature.
      logger?.debug?.(`report build with store failed, retrying with snapshot: ${storeError.message}`);
      try {
        built = await reportModule.buildReport(await store.snapshot());
      } catch (snapshotError) {
        throw new HttpError(500, 'report.failed', `Report generation failed: ${snapshotError.message}`);
      }
    }
    const payload = format === 'md' ? built?.markdown : format === 'html' ? built?.html : format === 'sarif' ? built?.sarif : built?.json;
    if (payload === undefined || payload === null) {
      throw new HttpError(500, 'report.failed', `Report module did not return content for format "${format}".`);
    }
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload, null, 2);
    res.writeHead(200, {
      'Content-Type': spec.type,
      'Cache-Control': 'no-store',
      'Content-Disposition': `inline; filename="vantage-${id}-report.${spec.ext}"`,
      'X-Content-Type-Options': 'nosniff'
    });
    res.end(body);
    logger?.debug?.(`report ${format} served for ${id} (${body.length} bytes)`);
  }

  async function route(req, res, url) {
    const pathname = url.pathname;
    const parts = pathname.split('/').filter(Boolean);
    // parts[0] is always 'api' because the caller only routes /api requests here.
    const method = req.method ?? 'GET';
    const [resource, id, sub, subId] = parts.slice(1);

    if (resource === 'health' && parts.length === 2) {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return health(req, res);
    }
    if (resource === 'events' && parts.length === 2) {
      return handleEvents(req, res, { bus, url, logger });
    }
    if (resource !== 'engagements') {
      throw new HttpError(404, 'not_found', 'Unknown API endpoint.');
    }

    // /api/engagements
    if (parts.length === 2) {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return listEngagements(req, res);
    }

    // /api/engagements/:id
    if (parts.length === 3) {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return engagementDetail(req, res, id);
    }

    const collection = sub;

    // /api/engagements/:id/findings
    if (parts.length === 4 && collection === 'findings') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return listFindings(req, res, id, url);
    }
    // /api/engagements/:id/findings/:fid
    if (parts.length === 5 && collection === 'findings') {
      if (method === 'GET') return findingDetail(req, res, id, subId);
      if (method === 'PATCH') return patchFinding(req, res, id, subId);
      return methodNotAllowed(res, ['GET', 'PATCH']);
    }
    // /api/engagements/:id/assets
    if (parts.length === 4 && collection === 'assets') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return listAssets(req, res, id, url);
    }
    // /api/engagements/:id/runs
    if (parts.length === 4 && collection === 'runs') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return listRuns(req, res, id);
    }
    // /api/engagements/:id/runs/:runId
    if (parts.length === 5 && collection === 'runs') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return runDetail(req, res, id, subId);
    }
    // /api/engagements/:id/evidence
    if (parts.length === 4 && collection === 'evidence') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return listEvidence(req, res, id, url);
    }
    // /api/engagements/:id/evidence/:evId
    if (parts.length === 5 && collection === 'evidence') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return evidenceDetail(req, res, id, subId);
    }
    // /api/engagements/:id/report
    if (parts.length === 4 && collection === 'report') {
      if (method !== 'GET') return methodNotAllowed(res, ['GET']);
      return report(req, res, id, url);
    }

    throw new HttpError(404, 'not_found', 'Unknown API endpoint.');
  }

  return async function handleApi(req, res, url) {
    try {
      await route(req, res, url);
    } catch (error) {
      if (res.headersSent || res.writableEnded) {
        if (!res.writableEnded) res.end();
        return;
      }
      const status = error?.status ?? (error instanceof NotFoundError ? 404 : error instanceof ConfigError ? 400 : 500);
      const code = error?.code && typeof error.code === 'string' ? error.code : status >= 500 ? 'internal.error' : 'request.invalid';
      const message = status >= 500 ? 'Internal server error.' : error?.message ?? 'Request failed.';
      if (status >= 500) logger?.error?.(`api ${req.method} ${url.pathname} failed: ${error?.stack ?? error?.message ?? error}`);
      else logger?.debug?.(`api ${req.method} ${url.pathname} -> ${status} ${code}`);
      sendJson(res, status, { error: message, code });
    }
  };
}

function clampInt(value, min, max, fallback) {
  if (value === null || value === undefined || value === '') return fallback;
  const number = Number(value);
  if (!Number.isInteger(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}
