import { appendJsonl, nowIso, readJsonl } from './util.js';

/**
 * Append-only audit trail of every network decision.
 *
 * Two things must be provable after an assessment: what we touched, and what we refused to touch.
 * Refusals are logged by the guard with `allowed: false`.
 */
export class AuditLog {
  /**
   * @param {{file: string, engagementId: string, runId?: string|null, sink?: (record: object) => void}} opts
   */
  constructor({ file, engagementId, runId = null, sink = null }) {
    this.file = file;
    this.engagementId = engagementId;
    this.runId = runId;
    this.sink = sink;
    this.writes = [];
    this.count = 0;
  }

  /** Attach the current run id (the guard does this when a run starts). */
  setRunId(runId) {
    this.runId = runId;
  }

  /**
   * Record one decision. Never throws: auditing must not break the assessment.
   * @param {{action: string, target?: string, host?: string, allowed?: boolean, reason?: string, module?: string, details?: object}} entry
   * @returns {Promise<object>} the stored record
   */
  async record(entry) {
    const record = {
      ts: nowIso(),
      engagementId: this.engagementId,
      runId: this.runId,
      action: entry.action,
      target: entry.target ?? null,
      host: entry.host ?? null,
      allowed: entry.allowed !== false,
      reason: entry.reason ?? '',
      module: entry.module ?? null,
      details: entry.details ?? null
    };
    this.count += 1;
    this.sink?.(record);
    this.writes.push(
      appendJsonl(this.file, record).catch(() => {
        // Disk-full or permission problems must not abort an assessment; the count still moves.
      })
    );
    // Keep the pending-write list bounded for long runs.
    if (this.writes.length > 64) await this.flush();
    return record;
  }

  async flush() {
    const pending = this.writes;
    this.writes = [];
    await Promise.all(pending);
  }

  /** Read this engagement's audit entries (newest last). */
  async read({ limit = 500 } = {}) {
    await this.flush();
    const rows = await readJsonl(this.file);
    return limit > 0 ? rows.slice(-limit) : rows;
  }

  /** Counts of allowed vs denied actions for reports. */
  async summary() {
    const rows = await readJsonl(this.file);
    const allowed = rows.filter((row) => row.allowed).length;
    return { total: rows.length, allowed, denied: rows.length - allowed };
  }
}
