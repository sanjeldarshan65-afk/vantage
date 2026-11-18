/**
 * Stable JSON report builder.
 *
 * The JSON report is the machine-readable deliverable: every other renderer starts from this same
 * normalized object so counts, ordering and vocabulary can never drift between formats.
 */
import { nowIso } from '../core/util.js';
import {
  REPORT_LIMITS,
  REPORT_SCHEMA_VERSION,
  VANTAGE_VERSION,
  buildLimitations,
  buildMethodology,
  buildSummary,
  computeCoverage,
  normalizeActivity,
  normalizeAssets,
  normalizeAudit,
  normalizeEngagement,
  normalizeFindings,
  normalizeRuns,
  normalizeScope
} from './shared.js';

/**
 * Count unique evidence identifiers referenced by findings. Used as a fallback when the snapshot
 * does not carry the store's evidence count.
 * @param {object[]} findings
 * @returns {number}
 */
function countReferencedEvidence(findings) {
  const ids = new Set();
  for (const finding of findings) {
    for (const id of finding.evidence) ids.add(id);
  }
  return ids.size;
}

/** Validate a snapshot timestamp, falling back to the current time. */
function reportTimestamp(value) {
  if (typeof value === 'string') {
    const date = new Date(value);
    if (!Number.isNaN(date.getTime())) return date.toISOString();
  }
  return nowIso();
}

/**
 * Build the normalized JSON report from an engagement snapshot.
 * @param {object} snapshot `EngagementStore.snapshot()` output or a fixture with the same shape
 * @returns {object} stable report object (`schemaVersion` 1)
 */
export function buildJsonReport(snapshot) {
  const input = snapshot && typeof snapshot === 'object' ? snapshot : {};
  const engagement = normalizeEngagement(input);
  const scope = normalizeScope(input, engagement);
  const findings = normalizeFindings(input.findings);
  const summary = buildSummary(findings);
  const allAssets = normalizeAssets(input.assets);
  const coverage = computeCoverage(allAssets);
  const runs = normalizeRuns(input.runs);
  const activity = normalizeActivity(input.activity);
  const audit = normalizeAudit(input.audit);

  const assets = allAssets.slice(0, REPORT_LIMITS.jsonAssets);
  const trimmedActivity = activity.slice(-REPORT_LIMITS.jsonActivity);
  const evidenceCount = Number.isFinite(Number(input.evidenceCount))
    ? Math.max(0, Math.trunc(Number(input.evidenceCount)))
    : countReferencedEvidence(findings);

  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: 'VANTAGE', version: VANTAGE_VERSION },
    generatedAt: reportTimestamp(input.generatedAt),
    engagement,
    scope,
    summary,
    coverage,
    findings,
    assets,
    assetsTotal: allAssets.length,
    assetsTruncated: allAssets.length > assets.length,
    runs,
    activity: trimmedActivity,
    activityTotal: activity.length,
    activityTruncated: activity.length > trimmedActivity.length,
    audit,
    evidenceCount,
    methodology: buildMethodology({ scope, runs, findings }),
    limitations: buildLimitations({ engagement, scope, runs, findings, assets: allAssets, evidenceCount })
  };
}
