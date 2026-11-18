import { newId, nowIso, shortHash, severityRank, SEVERITY_ORDER } from './util.js';

/**
 * Severity, confidence, proof-of-evidence and lifecycle vocabulary shared by every check,
 * the report and the dashboard.
 */
export const SEVERITIES = Object.freeze([...SEVERITY_ORDER]);
export const CONFIDENCES = Object.freeze(['confirmed', 'likely', 'possible']);
export const POE_LEVELS = Object.freeze(['observed', 'verified']);
export const STATUSES = Object.freeze(['open', 'fixed', 'accepted', 'false_positive', 'not_observed']);

const TITLE_MAX = 160;

function pick(value, allowed, fallback) {
  const normalized = String(value ?? '').toLowerCase();
  return allowed.includes(normalized) ? normalized : fallback;
}

/**
 * Canonical dedupe key: the same check at the same target with the same observed values is the
 * same finding, no matter which run reported it.
 */
export function findingKey({ check, target, observed }) {
  const observedText = (observed ?? [])
    .map((item) => `${item?.key ?? ''}=${item?.value ?? ''}`)
    .sort()
    .join('&');
  return shortHash(`${check}|${target}|${observedText}`);
}

/**
 * Normalize a finding contributed by a module.
 * @param {object} partial module-provided fields
 * @param {{engagementId: string, runId?: string|null, now?: string}} context
 * @returns {object} complete finding record
 */
export function normalizeFinding(partial, context) {
  if (!partial || typeof partial !== 'object') throw new TypeError('Finding must be an object.');
  const check = String(partial.check ?? '').trim();
  if (!/^[a-z0-9]+(?:\.[a-z0-9-]+)+$/i.test(check)) {
    throw new TypeError(`Finding check must look like "phase.module.slug", got "${check}"`);
  }
  const title = String(partial.title ?? '').trim();
  if (!title) throw new TypeError(`Finding ${check} is missing a title.`);

  const target = String(partial.target ?? partial.asset?.value ?? 'unknown');
  const severity = pick(partial.severity, SEVERITIES, 'info');
  const evidence = Array.isArray(partial.evidence) ? partial.evidence.filter(Boolean).map(String) : [];
  const confidence = pick(partial.confidence, CONFIDENCES, evidence.length > 0 ? 'confirmed' : 'likely');
  const poe = pick(partial.poe, POE_LEVELS, 'observed');
  const status = pick(partial.status, STATUSES, 'open');
  const now = context.now ?? nowIso();
  const observed = (Array.isArray(partial.observed) ? partial.observed : [])
    .filter((item) => item && typeof item === 'object')
    .map((item) => ({ key: String(item.key ?? ''), value: String(item.value ?? '') }));

  const finding = {
    id: partial.id ?? newId('fnd'),
    engagementId: context.engagementId,
    runId: context.runId ?? null,
    check,
    title: title.length > TITLE_MAX ? `${title.slice(0, TITLE_MAX - 1)}…` : title,
    severity,
    severityRank: severityRank(severity),
    confidence,
    poe,
    status,
    target,
    assetId: partial.assetId ?? partial.asset?.id ?? null,
    description: String(partial.description ?? ''),
    impact: String(partial.impact ?? ''),
    remediation: String(partial.remediation ?? ''),
    observed,
    evidence,
    references: (Array.isArray(partial.references) ? partial.references : []).filter((url) => /^https?:\/\//.test(String(url))),
    cwe: (Array.isArray(partial.cwe) ? partial.cwe : []).map(String),
    owasp: (Array.isArray(partial.owasp) ? partial.owasp : []).map(String),
    firstSeen: partial.firstSeen ?? now,
    lastSeen: now,
    occurrences: partial.occurrences ?? 1,
    history: Array.isArray(partial.history) ? partial.history : [{ ts: now, actor: 'engine', event: 'created', from: null, to: 'open', note: '' }]
  };
  finding.dedupeKey = partial.dedupeKey ?? findingKey(finding);
  return finding;
}

/** Merge a re-observed finding into the stored one (bumps counters, unions evidence). */
export function mergeFinding(existing, incoming, now = nowIso()) {
  const evidence = new Set([...(existing.evidence ?? []), ...(incoming.evidence ?? [])]);
  const observedMap = new Map();
  for (const item of [...(existing.observed ?? []), ...(incoming.observed ?? [])]) observedMap.set(`${item.key}\u0000${item.value}`, item);
  const reopened = existing.status === 'fixed';
  const history = [...(existing.history ?? [])];
  if (reopened) {
    history.push({ ts: now, actor: 'engine', event: 'reopened', from: 'fixed', to: 'open', note: 're-observed in a later run' });
  }
  return {
    ...existing,
    title: incoming.title ?? existing.title,
    severity: incoming.severity ?? existing.severity,
    severityRank: severityRank(incoming.severity ?? existing.severity),
    confidence: incoming.confidence ?? existing.confidence,
    description: incoming.description || existing.description,
    impact: incoming.impact || existing.impact,
    remediation: incoming.remediation || existing.remediation,
    observed: [...observedMap.values()],
    evidence: [...evidence],
    references: [...new Set([...(existing.references ?? []), ...(incoming.references ?? [])])],
    cwe: [...new Set([...(existing.cwe ?? []), ...(incoming.cwe ?? [])])],
    owasp: [...new Set([...(existing.owasp ?? []), ...(incoming.owasp ?? [])])],
    assetId: incoming.assetId ?? existing.assetId ?? null,
    lastSeen: now,
    occurrences: (existing.occurrences ?? 1) + 1,
    history,
    // A re-observation reopens a finding that was marked fixed.
    status: reopened ? 'open' : existing.status
  };
}

/** Count findings by severity and status. */
export function summarizeFindings(findings) {
  const bySeverity = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  const byStatus = Object.fromEntries(STATUSES.map((status) => [status, 0]));
  const byCheck = {};
  for (const finding of findings) {
    bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
    byStatus[finding.status] = (byStatus[finding.status] ?? 0) + 1;
    byCheck[finding.check] = (byCheck[finding.check] ?? 0) + 1;
  }
  const riskScore = findings.reduce((sum, finding) => {
    const weights = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
    return sum + (weights[finding.severity] ?? 0);
  }, 0);
  return {
    total: findings.length,
    open: byStatus.open ?? 0,
    bySeverity,
    byStatus,
    byCheck,
    riskScore,
    highest: findings.length === 0 ? null : [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
  };
}

/** True when a finding carries enough proof to be reported as verified. */
export function isVerifiable(finding) {
  return finding.poe === 'verified' && (finding.evidence?.length ?? 0) > 0;
}

/** A short one-line description for tables. */
export function findingLine(finding) {
  return `${finding.severity.toUpperCase().padEnd(8)} ${finding.title} — ${finding.target}`;
}
