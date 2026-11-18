import { PHASES } from './defaults.js';
import { loadModules } from './registry.js';
import { openWebTarget, joinUrl } from './webprobe.js';
import { LimitError, ScopeError, VantageError } from './errors.js';
import { newId, nowIso } from './util.js';
import { summarizeFindings } from './findings.js';

const DEFAULT_MODULE_TIMEOUT_MS = 180000;

/**
 * Race a module against its abort signal. Without this, a module stuck on a promise that ignores
 * `ctx.signal` would hang the whole run past its timeout.
 */
function raceWithAbort(promise, signal) {
  if (signal.aborted) return Promise.reject(new VantageError('module.aborted', 'module aborted'));
  let onAbort;
  const abortPromise = new Promise((_, reject) => {
    onAbort = () => reject(new VantageError('module.aborted', 'module aborted before it finished'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  return Promise.race([promise, abortPromise]).finally(() => signal.removeEventListener('abort', onAbort));
}

function portSuffix(port, scheme) {
  const defaultPort = scheme === 'https' ? 443 : 80;
  return port && port !== defaultPort ? `:${port}` : '';
}

/**
 * Derive the run's targets from the scope rules plus endpoints/services discovered in earlier
 * phases. Wildcards and CIDRs cannot produce a URL on their own; recon modules enumerate them.
 */
export function deriveTargets(store, scope) {
  const targets = [];
  const seen = new Set();
  const add = (target) => {
    const key = target.url ?? `${target.host}|${target.scheme}|${target.port}|${target.wildcard ?? ''}|${target.cidr ?? ''}`;
    if (seen.has(key)) return;
    seen.add(key);
    targets.push(target);
  };
  for (const rule of scope.targets) {
    switch (rule.type) {
      case 'url':
        add({ host: rule.host, url: `${rule.scheme}://${rule.host}${portSuffix(rule.port, rule.scheme)}`, scheme: rule.scheme, port: rule.port });
        break;
      case 'host':
      case 'ip':
        add({ host: rule.value, url: null, scheme: null, port: null });
        break;
      case 'wildcard':
        add({ host: null, url: null, scheme: null, port: null, wildcard: rule.suffix });
        break;
      case 'cidr':
        add({ host: null, url: null, scheme: null, port: null, cidr: rule.describe });
        break;
      default:
        break;
    }
  }
  for (const asset of store.listAssets({ type: 'endpoint' })) {
    try {
      const url = new URL(asset.value);
      add({ host: url.hostname, url: asset.value, scheme: url.protocol.slice(0, -1), port: url.port ? Number(url.port) : null });
    } catch {
      // ignore malformed discovered endpoints
    }
  }
  for (const asset of store.listAssets({ type: 'service' })) {
    const port = Number(asset.attributes?.port);
    if (!Number.isInteger(port)) continue;
    const scheme = port === 443 || port === 8443 || port === 9443 ? 'https' : 'http';
    const host = asset.value.includes(':') ? asset.value.slice(0, asset.value.lastIndexOf(':')) : asset.value;
    add({ host, url: null, scheme, port });
  }
  return targets;
}

/**
 * Runs assessment modules in phase order, one at a time, and persists a run record.
 *
 * A failing module never stops the run: its error is recorded and the next module proceeds.
 * Progress is emitted as events for the CLI live view and the dashboard SSE stream.
 */
export class Engine {
  /**
   * @param {{store: import('./store.js').EngagementStore, guard: import('./guard.js').ScopeGuard,
   *   logger: object, registry?: object, options?: object}} opts
   */
  constructor({ store, guard, logger, registry = null, options = {} }) {
    this.store = store;
    this.guard = guard;
    this.logger = logger;
    this.registry = registry;
    this.options = options;
    this.handlers = new Set();
  }

  /** Subscribe to progress events. Returns an unsubscribe function. */
  on(handler) {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  #emit(event) {
    for (const handler of this.handlers) {
      try {
        handler(event);
      } catch {
        // A broken UI subscriber must never break the assessment.
      }
    }
  }

  async #modules() {
    if (this.registry) return this.registry;
    this.registry = await loadModules();
    return this.registry;
  }

  /**
   * Run the assessment.
   * @param {{phases?: string[], only?: string[], signal?: AbortSignal, reconcile?: boolean,
   *   moduleTimeoutMs?: number, target?: object}} [options]
   * @returns {Promise<{run: object, summary: object, modules: object[]}>}
   */
  async run({ phases = PHASES, only = null, signal = null, reconcile = false, moduleTimeoutMs = DEFAULT_MODULE_TIMEOUT_MS, target = null } = {}) {
    const registry = await this.#modules();
    const selected = only && only.length > 0 ? new Set(only) : null;
    const targets = target ? [target] : deriveTargets(this.store, this.guard.scope);
    const primary = targets.find((entry) => entry.host && !entry.wildcard && !entry.cidr) ?? targets[0] ?? null;
    if (!primary) throw new VantageError('run.no-target', 'The engagement scope produced no scannable target.');

    const runId = newId('run');
    this.store.setRun(runId);
    const startedAt = nowIso();
    const startedHr = process.hrtime.bigint();
    const findingsBefore = this.store.findings.length;
    const assetsBefore = this.store.assets.length;
    const modulesRun = [];
    let aborted = false;
    let limited = false;

    this.guard.setRun(runId);
    this.#emit({ type: 'run:start', runId, startedAt, targets, phases, only: selected ? [...selected] : null });
    this.logger.info?.(`run ${runId} starting (${registry.size} modules, mode ${this.guard.scope.mode})`);

    const plan = [];
    for (const phase of phases) {
      for (const module of registry.byPhase(phase)) {
        if (selected && !selected.has(module.id)) continue;
        plan.push({ phase, module });
      }
    }
    if (plan.length === 0) throw new VantageError('run.no-modules', 'No modules matched this run.');

    for (const { phase, module } of plan) {
      if (signal?.aborted) {
        aborted = true;
        break;
      }
      const entry = { id: module.id, phase, title: module.title ?? module.id, status: 'running', startedAt: nowIso(), findings: 0, assets: 0, ms: 0 };
      const moduleStarted = process.hrtime.bigint();
      this.guard.setModule(module.id);
      this.#emit({ type: 'module:start', runId, phase, module: entry, target: primary });
      this.logger.info?.(`[${phase}] ${module.id} — ${module.title ?? ''}`);
      await this.store.note(`running ${module.id}`, { phase, runId });

      const controller = new AbortController();
      const onRunAbort = () => controller.abort();
      signal?.addEventListener('abort', onRunAbort, { once: true });
      const timer = setTimeout(() => controller.abort(), moduleTimeoutMs);
      timer.unref?.();

      const findingsBeforeModule = this.store.findings.length;
      const assetsBeforeModule = this.store.assets.length;
      const ctx = this.#createContext({ module, runId, signal: controller.signal, primary, targets, findingsBeforeModule });

      try {
        await raceWithAbort(module.run(ctx), controller.signal);
        entry.status = 'done';
      } catch (error) {
        if (signal?.aborted) {
          aborted = true;
          entry.status = 'aborted';
          entry.error = 'run cancelled';
        } else if (error instanceof LimitError) {
          limited = true;
          entry.status = 'limited';
          entry.error = error.message;
          this.logger.warn?.(`${module.id} stopped: ${error.message}`);
        } else if (error instanceof ScopeError) {
          entry.status = 'blocked';
          entry.error = error.message;
          this.logger.warn?.(`${module.id} blocked by scope: ${error.message}`);
        } else if (controller.signal.aborted && !signal?.aborted) {
          entry.status = 'timeout';
          entry.error = `module exceeded ${moduleTimeoutMs}ms`;
          this.logger.warn?.(`${module.id} timed out after ${moduleTimeoutMs}ms`);
        } else {
          entry.status = 'failed';
          entry.error = error?.message ?? String(error);
          this.logger.error?.(`${module.id} failed: ${entry.error}`);
        }
      } finally {
        clearTimeout(timer);
        signal?.removeEventListener('abort', onRunAbort);
      }

      entry.ms = Number((process.hrtime.bigint() - moduleStarted) / 1_000_000n);
      entry.findings = this.store.findings.length - findingsBeforeModule;
      entry.assets = this.store.assets.length - assetsBeforeModule;
      entry.endedAt = nowIso();
      modulesRun.push(entry);
      this.#emit({ type: 'module:done', runId, module: entry });
      await this.store.note(`${module.id} ${entry.status} (${entry.findings} findings, ${entry.assets} assets)`, { module: entry });

      if (limited) break;
    }

    const endedAt = nowIso();
    const elapsedMs = Number((process.hrtime.bigint() - startedHr) / 1_000_000n);
    const runFindings = this.store.findings.slice(findingsBefore);
    const stats = this.guard.stats();
    const run = {
      id: runId,
      engagementId: this.store.id,
      status: aborted ? 'aborted' : limited ? 'limited' : 'completed',
      startedAt,
      endedAt,
      elapsedMs,
      mode: this.guard.scope.mode,
      target: primary,
      phases,
      modules: modulesRun,
      stats: {
        modules: modulesRun.length,
        findings: runFindings.length,
        assets: this.store.assets.length - assetsBefore,
        requests: stats.requests,
        denials: stats.denials,
        evidence: await this.store.evidence.count()
      },
      summary: summarizeFindings(this.store.listFindings())
    };

    if (reconcile) run.reconcile = await this.store.reconcile(runFindings.map((finding) => finding.dedupeKey));

    await this.store.saveRun(run);
    await this.store.note(`run ${runId} ${run.status} in ${elapsedMs}ms`, { runId, status: run.status });
    await this.store.flush();
    this.#emit({ type: 'run:done', runId, run });
    this.logger.info?.(`run ${runId} ${run.status}: ${run.stats.findings} findings, ${run.stats.requests} requests`);

    return { run, summary: summarizeFindings(runFindings), modules: modulesRun };
  }

  /** Build the per-module context object described in ENGINEERING.md. */
  #createContext({ module, runId, signal, primary, targets, findingsBeforeModule }) {
    const store = this.store;
    const guard = this.guard;
    const logger = this.logger.child?.(module.id) ?? this.logger;
    const moduleOptions = {
      ...(module.defaults ?? {}),
      ...(store.options?.[module.id] ?? {}),
      ...(this.options?.[module.id] ?? {})
    };
    const probeCache = new Map();
    const assetsBaseline = store.assets.length;
    const emit = (event) => this.#emit(event);

    return {
      engagement: store.engagement,
      scope: guard.scope,
      guard,
      http: { requestOnce: (url, options) => guard.fetch(url, options) },
      dns: guard.dns,
      store,
      logger,
      signal,
      runId,
      module: { id: module.id, phase: module.phase, title: module.title },
      target: primary,
      targets,
      options: { module: moduleOptions, engagement: store.options, mode: guard.scope.mode },
      helpers: { joinUrl },

      /** Contribute one finding (normalized, deduped, persisted, emitted). */
      async addFinding(partial) {
        const finding = await store.addFinding({ ...partial, moduleId: module.id });
        if (partial.asset && partial.asset.type && partial.asset.value) {
          const asset = await store.addAsset(partial.asset);
          if (!finding.assetId) finding.assetId = asset.id;
          await store.touchAsset(asset, 'tested');
        }
        emit({ type: 'finding', runId, module: module.id, finding });
        return finding;
      },

      /** Register one discovered asset. */
      async addAsset(partial) {
        const asset = await store.addAsset(partial);
        void assetsBaseline;
        emit({ type: 'asset', runId, module: module.id, asset });
        return asset;
      },

      /** Append to the engagement activity feed. */
      async note(message, data) {
        return store.note(message, { module: module.id, ...(data ?? {}) });
      },

      /** Resolve (and cache) the web root of the target. */
      async openWebTarget(targetOverride) {
        const key = targetOverride?.url ?? 'primary';
        if (probeCache.has(key)) return probeCache.get(key);
        const probe = await openWebTarget(guard, targetOverride ?? primary, { logger, signal });
        probeCache.set(key, probe);
        return probe;
      },

      /** Findings contributed by this module so far (useful for end-of-module summaries). */
      contributedFindings() {
        return store.findings.slice(findingsBeforeModule);
      }
    };
  }
}
