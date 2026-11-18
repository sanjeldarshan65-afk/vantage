import path from 'node:path';
import { promises as fs } from 'node:fs';
import { FILES, engagementsDir, isValidEngagementId } from './paths.js';
import { normalizeEngagement } from './scope.js';
import { ConfigError, NotFoundError } from './errors.js';
import { AuditLog } from './audit.js';
import { EvidenceStore } from './evidence.js';
import { mergeFinding, normalizeFinding, summarizeFindings, STATUSES } from './findings.js';
import {
  appendJsonl,
  ensureDir,
  newId,
  nowIso,
  percent,
  readJson,
  readJsonl,
  severityRank,
  writeJsonAtomic
} from './util.js';

/** Asset vocabulary. Coverage and the graph use exactly these types. */
export const ASSET_TYPES = Object.freeze(['domain', 'subdomain', 'ip', 'service', 'endpoint']);

const FINDING_STATUSES = new Set(STATUSES);

function assetKey(type, value) {
  return `${type}|${value}`;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/**
 * One engagement's persistent store: metadata, findings, assets, activity, runs, evidence, audit.
 *
 * Findings and assets are held in memory and written atomically (debounced). Every mutation is
 * visible to the dashboard through `snapshot()`.
 */
export class EngagementStore {
  constructor({ id, dir, document, logger = null }) {
    const { engagement, scope, options } = normalizeEngagement(document);
    this.id = id;
    this.dir = dir;
    this.engagement = engagement;
    this.scope = scope;
    this.options = options;
    this.logger = logger;
    this.findings = [];
    this.assets = [];
    this.assetIndex = new Map();
    this.runs = [];
    this.runId = null;
    this.activityFeed = [];
    this.audit = new AuditLog({ file: this.file(FILES.audit), engagementId: id });
    this.evidence = new EvidenceStore({ file: this.file(FILES.evidence), engagementId: id });
    this.#persistChain = Promise.resolve();
    this.#persistTimer = null;
  }

  #persistChain;
  #persistTimer;

  /** Absolute path of a file inside the engagement directory. */
  file(name) {
    return path.join(this.dir, name);
  }

  /** Resolve the directory that holds engagement folders. */
  static #root(engagementsRoot) {
    return engagementsRoot ? path.resolve(engagementsRoot) : engagementsDir();
  }

  /** Open an existing engagement. */
  static async open(id, { engagementsRoot, logger = null } = {}) {
    if (!isValidEngagementId(id)) throw new ConfigError(`Invalid engagement id: ${id}`);
    const dir = path.join(EngagementStore.#root(engagementsRoot), id);
    const document = await readJson(path.join(dir, FILES.engagement), null);
    if (!document) throw new NotFoundError(`Engagement "${id}" not found in ${dir}`);
    const store = new EngagementStore({ id, dir, document, logger });
    await store.#load();
    return store;
  }

  /** Create a new engagement from a document; refuses to overwrite by default. */
  static async create(document, { engagementsRoot, logger = null, overwrite = false } = {}) {
    const normalized = normalizeEngagement(document);
    const id = normalized.engagement.id;
    const dir = path.join(EngagementStore.#root(engagementsRoot), id);
    const exists = await fs
      .access(path.join(dir, FILES.engagement))
      .then(() => true)
      .catch(() => false);
    if (exists && !overwrite) throw new ConfigError(`Engagement "${id}" already exists at ${dir}. Use --force to overwrite.`);
    await ensureDir(dir);
    if (overwrite) {
      // Re-initializing an engagement starts from a clean slate: results from the old
      // configuration would be unverifiable against the new scope.
      for (const name of [FILES.findings, FILES.assets, FILES.audit, FILES.evidence, FILES.activity]) {
        await fs.rm(path.join(dir, name), { force: true });
      }
      await fs.rm(path.join(dir, FILES.runs), { recursive: true, force: true });
      await fs.rm(path.join(dir, FILES.reports), { recursive: true, force: true });
    }
    await writeJsonAtomic(path.join(dir, FILES.engagement), document);
    const store = new EngagementStore({ id, dir, document, logger });
    await store.#load();
    return store;
  }

  /** Does an engagement exist? */
  static async exists(id, { engagementsRoot } = {}) {
    const dir = path.join(EngagementStore.#root(engagementsRoot), id);
    return fs
      .access(path.join(dir, FILES.engagement))
      .then(() => true)
      .catch(() => false);
  }

  /** List engagement summaries (newest activity first). */
  static async list({ engagementsRoot } = {}) {
    const root = EngagementStore.#root(engagementsRoot);
    let entries = [];
    try {
      entries = await fs.readdir(root);
    } catch {
      return [];
    }
    const summaries = [];
    for (const entry of entries) {
      if (!isValidEngagementId(entry)) continue;
      const dir = path.join(root, entry);
      const document = await readJson(path.join(dir, FILES.engagement), null);
      if (!document) continue;
      let engagement;
      try {
        engagement = normalizeEngagement(document).engagement;
      } catch {
        continue;
      }
      const findings = await readJson(path.join(dir, FILES.findings), []);
      const assets = await readJson(path.join(dir, FILES.assets), []);
      let runs = [];
      try {
        runs = (await fs.readdir(path.join(dir, FILES.runs))).filter((name) => name.endsWith('.json'));
      } catch {
        runs = [];
      }
      summaries.push({
        id: engagement.id,
        name: engagement.name,
        client: engagement.client,
        mode: engagement.mode,
        authorizationRef: engagement.authorizationRef,
        endsAt: engagement.endsAt,
        findings: findings.length,
        assets: assets.length,
        runs: runs.length,
        // Run ids are random, so the newest run comes from its startedAt, not its file name.
        lastRunAt: (await Promise.all(runs.map((name) => readJson(path.join(dir, FILES.runs, name), null))))
          .map((run) => run?.startedAt)
          .filter((ts) => typeof ts === 'string' && !Number.isNaN(Date.parse(ts)))
          .sort()
          .at(-1) ?? null
      });
    }
    return summaries.sort((a, b) => String(b.lastRunAt ?? '').localeCompare(String(a.lastRunAt ?? '')));
  }

  async #load() {
    this.findings = (await readJson(this.file(FILES.findings), [])) || [];
    this.assets = (await readJson(this.file(FILES.assets), [])) || [];
    this.assetIndex = new Map(this.assets.map((asset) => [assetKey(asset.type, asset.value), asset]));
    const activity = await readJsonl(this.file(FILES.activity));
    this.activityFeed = activity.slice(-300);
    await this.#loadRuns();
  }

  async #loadRuns() {
    let names = [];
    try {
      names = await fs.readdir(this.file(FILES.runs));
    } catch {
      names = [];
    }
    const runs = [];
    for (const name of names) {
      if (!name.endsWith('.json')) continue;
      const run = await readJson(path.join(this.file(FILES.runs), name), null);
      if (run) runs.push(run);
    }
    this.runs = runs.sort((a, b) => String(a.startedAt).localeCompare(String(b.startedAt)));
  }

  /** Bind the run id that new findings/assets/evidence belong to. */
  setRun(runId) {
    this.runId = runId;
    this.audit.setRunId(runId);
  }

  /* ------------------------------------------------------------------ findings */

  /**
   * Add or merge one finding. Dedupe key is check + target + observed values, so re-running the
   * same check updates the existing finding instead of duplicating it.
   * @param {object} partial
   * @returns {Promise<object>} persisted finding
   */
  async addFinding(partial) {
    const normalized = normalizeFinding(partial, { engagementId: this.id, runId: this.runId });
    const index = this.findings.findIndex((finding) => finding.dedupeKey === normalized.dedupeKey);
    let stored;
    if (index === -1) {
      this.findings.push(normalized);
      stored = normalized;
    } else {
      stored = mergeFinding(this.findings[index], normalized, nowIso());
      this.findings[index] = stored;
    }
    await this.#persist();
    return stored;
  }

  /** All findings, filtered and severity-sorted. */
  listFindings({ severity, status, check, search, sort = 'severity' } = {}) {
    let rows = [...this.findings];
    if (severity) rows = rows.filter((finding) => finding.severity === severity);
    if (status) rows = rows.filter((finding) => finding.status === status);
    if (check) rows = rows.filter((finding) => finding.check === check);
    if (search) {
      const needle = String(search).toLowerCase();
      rows = rows.filter((finding) =>
        [finding.title, finding.check, finding.target, finding.description].join(' ').toLowerCase().includes(needle)
      );
    }
    rows.sort((a, b) => {
      if (sort === 'recent') return String(b.lastSeen).localeCompare(String(a.lastSeen));
      if (sort === 'title') return a.title.localeCompare(b.title);
      const rank = severityRank(a.severity) - severityRank(b.severity);
      return rank !== 0 ? rank : a.title.localeCompare(b.title);
    });
    return rows;
  }

  getFinding(id) {
    return this.findings.find((finding) => finding.id === id) ?? null;
  }

  /**
   * Change a finding's lifecycle status, appending to its history.
   * @returns {Promise<object|null>}
   */
  async updateFinding(id, { status, note = '', actor = 'operator', severity } = {}) {
    const finding = this.getFinding(id);
    if (!finding) return null;
    if (status && !FINDING_STATUSES.has(status)) throw new ConfigError(`Unknown finding status "${status}".`);
    const from = finding.status;
    if (status) finding.status = status;
    if (severity && ['critical', 'high', 'medium', 'low', 'info'].includes(severity)) {
      finding.severity = severity;
      finding.severityRank = severityRank(severity);
    }
    finding.history = finding.history ?? [];
    finding.history.push({ ts: nowIso(), actor, event: status ? 'status_changed' : 'annotated', from, to: finding.status, note });
    await this.#persist();
    return finding;
  }

  /**
   * Mark findings that were not observed in the latest run (used by `retest`).
   * @param {string[]} observedKeys dedupe keys seen in the run
   * @returns {Promise<{markedNotObserved: number, reopened: number}>}
   */
  async reconcile(observedKeys) {
    const seen = new Set(observedKeys);
    let markedNotObserved = 0;
    let reopened = 0;
    for (const finding of this.findings) {
      if (finding.status === 'fixed' || finding.status === 'accepted' || finding.status === 'false_positive') continue;
      if (seen.has(finding.dedupeKey)) {
        if (finding.status === 'not_observed') {
          finding.status = 'open';
          reopened += 1;
          finding.history?.push({ ts: nowIso(), actor: 'engine', event: 'status_changed', from: 'not_observed', to: 'open', note: 're-observed in retest' });
        }
        continue;
      }
      if (finding.status === 'open') {
        finding.status = 'not_observed';
        markedNotObserved += 1;
        finding.history?.push({ ts: nowIso(), actor: 'engine', event: 'status_changed', from: 'open', to: 'not_observed', note: 'not reproduced in retest' });
      }
    }
    if (markedNotObserved > 0 || reopened > 0) await this.#persist();
    return { markedNotObserved, reopened };
  }

  /* -------------------------------------------------------------------- assets */

  /**
   * Add or merge an asset (dedupe: type + value).
   * @param {{type: string, value: string, parent?: string|object|null, attributes?: object, state?: string}} partial
   */
  async addAsset(partial) {
    const type = String(partial?.type ?? '').toLowerCase();
    const value = String(partial?.value ?? '').trim();
    if (!ASSET_TYPES.includes(type)) throw new ConfigError(`Unknown asset type "${type}" (expected one of ${ASSET_TYPES.join(', ')}).`);
    if (!value) throw new ConfigError('Asset needs a value.');
    const key = assetKey(type, value);
    let asset = this.assetIndex.get(key);
    if (!asset) {
      asset = {
        id: newId('ast'),
        engagementId: this.id,
        type,
        value,
        parentId: this.#resolveParent(partial.parent),
        attributes: isPlainObject(partial.attributes) ? { ...partial.attributes } : {},
        state: partial.state === 'tested' ? 'tested' : 'untested',
        firstSeen: nowIso(),
        lastSeen: nowIso()
      };
      this.assets.push(asset);
      this.assetIndex.set(key, asset);
    } else {
      asset.lastSeen = nowIso();
      if (isPlainObject(partial.attributes)) asset.attributes = { ...asset.attributes, ...partial.attributes };
      const parentId = this.#resolveParent(partial.parent);
      if (parentId && !asset.parentId) asset.parentId = parentId;
      if (partial.state === 'tested') asset.state = 'tested';
    }
    await this.#persist();
    return asset;
  }

  /** Mark an asset as tested (or untested). Accepts an asset id, or `{type, value}`. */
  async touchAsset(ref, state = 'tested') {
    const asset = typeof ref === 'string' ? this.assets.find((entry) => entry.id === ref) : this.assets.find((entry) => entry.type === ref?.type && entry.value === ref?.value);
    if (!asset) return null;
    const changed = asset.state !== state;
    asset.state = state;
    asset.lastSeen = nowIso();
    if (changed) await this.#persist();
    return asset;
  }

  #resolveParent(parent) {
    if (!parent) return null;
    if (typeof parent === 'string') {
      const byId = this.assets.find((asset) => asset.id === parent);
      if (byId) return byId.id;
      const byValue = this.assets.find((asset) => asset.value === parent);
      return byValue?.id ?? null;
    }
    if (typeof parent === 'object') {
      if (parent.id) return parent.id;
      const match = this.assets.find((asset) => asset.type === parent.type && asset.value === parent.value);
      return match?.id ?? null;
    }
    return null;
  }

  /** Assets, optionally filtered. */
  listAssets({ type, state } = {}) {
    let rows = [...this.assets];
    if (type) rows = rows.filter((asset) => asset.type === type);
    if (state) rows = rows.filter((asset) => asset.state === state);
    return rows;
  }

  /** Coverage ledger: tested vs untested per asset type. */
  coverage() {
    const byType = {};
    for (const type of ASSET_TYPES) byType[type] = { total: 0, tested: 0, untested: 0 };
    for (const asset of this.assets) {
      const bucket = byType[asset.type] ?? (byType[asset.type] = { total: 0, tested: 0, untested: 0 });
      bucket.total += 1;
      if (asset.state === 'tested') bucket.tested += 1;
      else bucket.untested += 1;
    }
    const total = this.assets.length;
    const tested = this.assets.filter((asset) => asset.state === 'tested').length;
    return { byType, total, tested, untested: total - tested, percentTested: percent(tested, total) };
  }

  /* ------------------------------------------------------------------ activity */

  /** Append to the human-readable activity feed and the logger. */
  async note(message, data = undefined) {
    const record = { ts: nowIso(), message: String(message), data: data ?? null };
    this.activityFeed.push(record);
    if (this.activityFeed.length > 300) this.activityFeed = this.activityFeed.slice(-300);
    await appendJsonl(this.file(FILES.activity), record).catch(() => {});
    return record;
  }

  activity(limit = 50) {
    return this.activityFeed.slice(-limit);
  }

  /* ----------------------------------------------------------------------- runs */

  /** Persist a run record under `runs/<runId>.json`. */
  async saveRun(run) {
    if (!run?.id) throw new ConfigError('Run record needs an id.');
    const record = { ...run, engagementId: this.id };
    await writeJsonAtomic(path.join(this.file(FILES.runs), `${run.id}.json`), record);
    const index = this.runs.findIndex((entry) => entry.id === record.id);
    if (index === -1) this.runs.push(record);
    else this.runs[index] = record;
    return record;
  }

  listRuns() {
    return [...this.runs].sort((a, b) => String(b.startedAt).localeCompare(String(a.startedAt)));
  }

  getRun(id) {
    return this.runs.find((run) => run.id === id) ?? null;
  }

  /* ------------------------------------------------------------------- snapshot */

  /** A serializable snapshot for reports and the dashboard. */
  async snapshot({ activityLimit = 50, includeAudit = true } = {}) {
    const findings = this.listFindings();
    return {
      generatedAt: nowIso(),
      engagement: { ...this.engagement, mode: this.scope.mode },
      scope: this.scope.describe(),
      options: this.options,
      findings,
      summary: summarizeFindings(findings),
      assets: this.listAssets(),
      coverage: this.coverage(),
      runs: this.listRuns(),
      activity: this.activity(activityLimit),
      evidenceCount: await this.evidence.count(),
      audit: includeAudit ? await this.audit.summary() : null
    };
  }

  /* --------------------------------------------------------------- persistence */

  #persist() {
    if (this.#persistTimer) return Promise.resolve();
    this.#persistTimer = setTimeout(() => {
      this.#persistTimer = null;
      this.#persistChain = this.#persistChain.then(() => this.#flush()).catch((error) => this.logger?.warn?.(`persist failed: ${error.message}`));
    }, 20);
    this.#persistTimer.unref?.();
    return this.#persistChain;
  }

  async #flush() {
    await writeJsonAtomic(this.file(FILES.findings), this.findings);
    await writeJsonAtomic(this.file(FILES.assets), this.assets);
  }

  /** Force all pending writes to disk. */
  async flush() {
    if (this.#persistTimer) {
      clearTimeout(this.#persistTimer);
      this.#persistTimer = null;
      this.#persistChain = this.#persistChain.then(() => this.#flush());
    }
    await this.#persistChain;
    await this.audit.flush();
    await this.evidence.flush();
  }

  /** Flush and release resources. */
  async close() {
    await this.flush();
  }
}

export { summarizeFindings };
