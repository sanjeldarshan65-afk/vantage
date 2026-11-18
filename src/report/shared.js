/**
 * Shared report helpers: frozen vocabulary mirrors, snapshot normalization, risk rating and
 * output escaping. Everything a report renderer needs lives here so the JSON, Markdown and HTML
 * builders can never disagree about ordering, counts or labels.
 *
 * Report modules are pure: they read a snapshot object (or a live store, handled in index.js) and
 * never touch the network or the target.
 */
import { SEVERITY_ORDER, severityRank, percent } from '../core/util.js';
export { SEVERITY_ORDER };
import { CONFIDENCES, POE_LEVELS, STATUSES, summarizeFindings } from '../core/findings.js';

/** Product version reported in the JSON metadata and in the print footer. */
export const VANTAGE_VERSION = '1.0.0';

/** Stable report schema version. Bump only on breaking shape changes. */
export const REPORT_SCHEMA_VERSION = 1;

/** Hard caps that keep a report readable and bounded regardless of engagement size. */
export const REPORT_LIMITS = Object.freeze({
  jsonAssets: 500,
  jsonActivity: 50,
  markdownAssets: 200,
  htmlAssets: 200,
  evidencePerFinding: 5,
  evidenceTotal: 40,
  evidenceBodyPreview: 800,
  observedValueChars: 4000,
  attributeValueChars: 400
});

/** Assessment depth. Mirrors core/scope.js; none of them enable exploitation. */
export const MODES = Object.freeze(['passive', 'safe', 'full']);

/** Asset vocabulary. Mirrors core/store.js ASSET_TYPES (frozen in ENGINEERING.md). */
export const ASSET_TYPES = Object.freeze(['domain', 'subdomain', 'ip', 'service', 'endpoint']);

/** Severity weights used by core summarizeFindings; repeated here for active-finding scoring. */
export const SEVERITY_WEIGHTS = Object.freeze({ critical: 10, high: 6, medium: 3, low: 1, info: 0 });

/** Display metadata for each severity; `color` is used by the print/dark stylesheet. */
export const SEVERITY_META = Object.freeze({
  critical: { key: 'critical', label: 'Critical', color: '#ff6b6b', rank: 1 },
  high: { key: 'high', label: 'High', color: '#ffa04d', rank: 2 },
  medium: { key: 'medium', label: 'Medium', color: '#ffd166', rank: 3 },
  low: { key: 'low', label: 'Low', color: '#5aa9ff', rank: 4 },
  info: { key: 'info', label: 'Info', color: '#9fb0c0', rank: 5 }
});

/** Display metadata for finding lifecycle statuses. */
export const STATUS_META = Object.freeze({
  open: { key: 'open', label: 'Open' },
  fixed: { key: 'fixed', label: 'Fixed' },
  accepted: { key: 'accepted', label: 'Accepted' },
  false_positive: { key: 'false_positive', label: 'False positive' },
  not_observed: { key: 'not_observed', label: 'Not observed' }
});

/** Display metadata for confidence levels. */
export const CONFIDENCE_META = Object.freeze({
  confirmed: { key: 'confirmed', label: 'Confirmed' },
  likely: { key: 'likely', label: 'Likely' },
  possible: { key: 'possible', label: 'Possible' }
});

/** Display metadata for proof-of-evidence levels. */
export const POE_META = Object.freeze({
  observed: { key: 'observed', label: 'Observed' },
  verified: { key: 'verified', label: 'Verified' }
});

/** Rating metadata used by every renderer. `none` is the empty-engagement rating. */
export const RISK_META = Object.freeze({
  critical: { key: 'critical', label: 'Critical' },
  high: { key: 'high', label: 'High' },
  medium: { key: 'medium', label: 'Medium' },
  low: { key: 'low', label: 'Low' },
  informational: { key: 'informational', label: 'Informational' },
  none: { key: 'none', label: 'None' }
});

/** Standard disclaimer rendered by both rich formats. */
export const REPORT_DISCLAIMER =
  'This report was produced by VANTAGE for the client named above under the authorization reference ' +
  'recorded in this document. It describes the state of the assessed systems at the time of testing and is ' +
  'limited to the scope, time window and check set recorded here. It is not a guarantee that the systems are ' +
  'free of vulnerabilities, and it does not constitute legal, compliance or certification advice. Distribution ' +
  'should be limited to parties authorized under the engagement.';

const HTML_ESCAPES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;'
});

/**
 * Escape a target-controlled string for HTML text and quoted attribute contexts.
 * All five HTML-significant characters are encoded, so the result is safe in either context.
 * @param {unknown} value
 * @returns {string}
 */
export function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"'`]/g, (char) => HTML_ESCAPES[char]);
}

/**
 * Escape a target-controlled string for inline Markdown. Raw HTML is neutralised (`<`, `>`, `&`)
 * and GFM syntax characters are backslash-escaped so hostile text cannot forge links or emphasis.
 * @param {unknown} value
 * @returns {string}
 */
export function escapeMarkdownInline(value) {
  return String(value ?? '')
    .replace(/\\/g, '\\\\')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/([`*_[\]|])/g, '\\$1');
}

/** Escape a value for a Markdown table cell (inline rules plus newline folding). */
export function escapeMarkdownCell(value) {
  return escapeMarkdownInline(value).replace(/\r?\n/g, ' ');
}

/**
 * Truncate text to `max` characters, appending an ellipsis when content was removed.
 * @param {unknown} value
 * @param {number} max
 * @returns {string}
 */
export function truncateText(value, max) {
  const text = String(value ?? '');
  if (!Number.isFinite(max) || max <= 0 || text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

/** `1 finding` / `3 findings` without string concatenation noise. */
export function countLabel(count, singular, plural = `${singular}s`) {
  return `${count} ${count === 1 ? singular : plural}`;
}

/** Label for a severity value (falls back to the raw value). */
export function severityLabel(severity) {
  return SEVERITY_META[severity]?.label ?? String(severity ?? 'Unknown');
}

/** Integer coercion that never returns NaN. */
function toInt(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.trunc(number) : fallback;
}

/** Non-negative integer coercion. */
function toCount(value) {
  return Math.max(0, toInt(value, 0));
}

/** Array coercion. */
function asArray(value) {
  return Array.isArray(value) ? value : [];
}

/** Trimmed string coercion. */
function asText(value) {
  return typeof value === 'string' ? value : value == null ? '' : String(value);
}

/** Validated enum coercion against a frozen vocabulary. */
function pickEnum(value, allowed, fallback) {
  const normalized = asText(value).toLowerCase();
  return allowed.includes(normalized) ? normalized : fallback;
}

/** Normalize any timestamp-ish value to an ISO string, or null when invalid. */
export function normalizeDateIso(value) {
  if (value == null || value === '') return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

const pad = (value) => String(value).padStart(2, '0');

/** Human UTC timestamp, e.g. `2026-11-18 12:00 UTC`. Locale independent by design. */
export function formatDate(value) {
  const iso = normalizeDateIso(value);
  if (!iso) return '—';
  const date = new Date(iso);
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`
  );
}

/** Compact filesystem-safe UTC stamp, e.g. `20261118-120000`. */
export function formatStamp(value = new Date()) {
  const date = value instanceof Date ? value : new Date(value);
  const valid = Number.isNaN(date.getTime()) ? new Date() : date;
  return (
    `${valid.getUTCFullYear()}${pad(valid.getUTCMonth() + 1)}${pad(valid.getUTCDate())}-` +
    `${pad(valid.getUTCHours())}${pad(valid.getUTCMinutes())}${pad(valid.getUTCSeconds())}`
  );
}

/** Duration formatter for tables, e.g. `420 ms`, `3.2 s`, `1m 05s`. */
export function formatDuration(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value < 0) return '—';
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60000) return `${(value / 1000).toFixed(1)} s`;
  const minutes = Math.floor(value / 60000);
  const seconds = Math.round((value % 60000) / 1000);
  return `${minutes}m ${pad(seconds)}s`;
}

/**
 * Normalize the engagement metadata block of a snapshot.
 * @param {object} snapshot
 * @returns {object}
 */
export function normalizeEngagement(snapshot) {
  const raw = snapshot && typeof snapshot.engagement === 'object' && snapshot.engagement ? snapshot.engagement : snapshot ?? {};
  const id = asText(raw.id).trim() || 'unknown-engagement';
  return {
    id,
    name: asText(raw.name).trim() || id,
    client: asText(raw.client).trim(),
    authorizedBy: asText(raw.authorizedBy).trim(),
    authorizationRef: asText(raw.authorizationRef).trim(),
    startsAt: normalizeDateIso(raw.startsAt),
    endsAt: normalizeDateIso(raw.endsAt),
    mode: pickEnum(raw.mode, MODES, 'safe'),
    notes: asText(raw.notes)
  };
}

/**
 * Normalize the scope block (targets, exclusions, ports, limits, mode).
 * @param {object} snapshot
 * @param {object} engagement already-normalized engagement
 * @returns {object}
 */
export function normalizeScope(snapshot, engagement) {
  const raw = snapshot && typeof snapshot.scope === 'object' && snapshot.scope ? snapshot.scope : {};
  const ports = raw.ports && typeof raw.ports === 'object' ? raw.ports : {};
  const limits = raw.limits && typeof raw.limits === 'object' ? raw.limits : {};
  return {
    mode: pickEnum(raw.mode ?? engagement.mode, MODES, engagement.mode),
    targets: asArray(raw.targets).map((target) => asText(target).trim()).filter(Boolean),
    exclude: asArray(raw.exclude).map((target) => asText(target).trim()).filter(Boolean),
    ports: {
      include: asArray(ports.include).map((port) => toInt(port, 0)).filter((port) => port > 0),
      exclude: asArray(ports.exclude).map((port) => toInt(port, 0)).filter((port) => port > 0)
    },
    limits: Object.fromEntries(
      Object.entries(limits)
        .filter(([, value]) => Number.isFinite(Number(value)))
        .map(([key, value]) => [key, Number(value)])
    ),
    allowThirdParty: Boolean(raw.allowThirdParty)
  };
}

/** Normalize one observed key/value pair. */
function normalizeObserved(observed) {
  return asArray(observed)
    .filter((item) => item && typeof item === 'object' && !Array.isArray(item))
    .map((item) => ({
      key: truncateText(asText(item.key), 200),
      value: truncateText(asText(item.value), REPORT_LIMITS.observedValueChars)
    }));
}

/**
 * Normalize one finding to the stable report shape. Internal bookkeeping (history, dedupe key,
 * severity rank) is dropped; everything a client needs is kept.
 * @param {object} raw
 * @returns {object}
 */
export function normalizeFinding(raw) {
  const finding = raw && typeof raw === 'object' ? raw : {};
  const severity = pickEnum(finding.severity, SEVERITY_ORDER, 'info');
  const firstSeen = normalizeDateIso(finding.firstSeen);
  const lastSeen = normalizeDateIso(finding.lastSeen);
  return {
    id: asText(finding.id).trim(),
    check: asText(finding.check).trim(),
    title: asText(finding.title).trim() || '(untitled finding)',
    severity,
    confidence: pickEnum(finding.confidence, CONFIDENCES, 'likely'),
    poe: pickEnum(finding.poe, POE_LEVELS, 'observed'),
    status: pickEnum(finding.status, STATUSES, 'open'),
    target: asText(finding.target).trim() || 'unknown',
    description: asText(finding.description),
    impact: asText(finding.impact),
    remediation: asText(finding.remediation),
    observed: normalizeObserved(finding.observed),
    evidence: asArray(finding.evidence).map((id) => asText(id).trim()).filter(Boolean),
    references: asArray(finding.references)
      .map((url) => asText(url).trim())
      .filter((url) => /^https?:\/\//i.test(url)),
    cwe: asArray(finding.cwe).map((value) => asText(value).trim()).filter(Boolean),
    owasp: asArray(finding.owasp).map((value) => asText(value).trim()).filter(Boolean),
    firstSeen,
    lastSeen,
    occurrences: Math.max(1, toInt(finding.occurrences, 1))
  };
}

/**
 * Normalize and severity-sort a list of findings (critical → info, then title, then id).
 * @param {object[]} findings
 * @returns {object[]}
 */
export function normalizeFindings(findings) {
  return asArray(findings)
    .filter((finding) => finding && typeof finding === 'object')
    .map(normalizeFinding)
    .sort((a, b) => {
      const rank = severityRank(a.severity) - severityRank(b.severity);
      if (rank !== 0) return rank;
      const byTitle = a.title.localeCompare(b.title);
      return byTitle !== 0 ? byTitle : a.id.localeCompare(b.id);
    });
}

/**
 * Derive the risk rating from active-finding severity counts and risk score.
 * Fixed and false-positive findings do not contribute to the rating.
 * @param {{total: number, bySeverity: object, riskScore: number}} active
 * @returns {{key: string, label: string, rationale: string}}
 */
export function computeRiskRating(active) {
  const counts = active.bySeverity ?? {};
  const score = active.riskScore ?? 0;
  const finish = (key, rationale) => ({ key, label: RISK_META[key].label, rationale });

  if (!active.total) {
    return finish('none', 'No active findings remain; only closed or false-positive findings are recorded.');
  }
  if (counts.critical > 0) {
    return finish('critical', 'Critical-severity findings are active and require immediate remediation.');
  }
  if (counts.high > 0) return finish('high', 'High-severity findings are active and should be remediated as a priority.');
  if (score >= 30) {
    return finish('high', `The aggregate risk score (${score}) from medium and low findings is high.`);
  }
  if (counts.medium > 0) return finish('medium', 'Medium-severity findings are active.');
  if (score >= 10) {
    return finish('medium', `The aggregate risk score (${score}) from low findings warrants attention.`);
  }
  if (counts.low > 0) return finish('low', 'Only low-severity findings are active.');
  return finish('informational', 'Only informational observations are active.');
}

/**
 * Build the report summary: all-finding counts (compatible with core `summarizeFindings`) plus
 * active-finding counts and the derived risk rating.
 * @param {object[]} findings normalized findings
 * @returns {object}
 */
export function buildSummary(findings) {
  const base = summarizeFindings(findings);
  const activeBySeverity = Object.fromEntries(SEVERITY_ORDER.map((severity) => [severity, 0]));
  let activeRiskScore = 0;
  let activeTotal = 0;
  for (const finding of findings) {
    if (finding.status === 'fixed' || finding.status === 'false_positive') continue;
    activeTotal += 1;
    activeBySeverity[finding.severity] = (activeBySeverity[finding.severity] ?? 0) + 1;
    activeRiskScore += SEVERITY_WEIGHTS[finding.severity] ?? 0;
  }
  const activeFindings = findings.filter((finding) => finding.status !== 'fixed' && finding.status !== 'false_positive');
  const highestActive = activeFindings.length
    ? [...activeFindings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0].severity
    : null;
  const rating = computeRiskRating({ total: activeTotal, bySeverity: activeBySeverity, riskScore: activeRiskScore });
  return {
    total: base.total,
    open: base.open,
    bySeverity: base.bySeverity,
    byStatus: base.byStatus,
    byCheck: base.byCheck,
    riskScore: base.riskScore,
    highest: base.highest,
    active: {
      total: activeTotal,
      bySeverity: activeBySeverity,
      riskScore: activeRiskScore,
      highest: highestActive
    },
    riskRating: rating.key,
    riskLabel: rating.label,
    riskRationale: rating.rationale
  };
}

/** Coerce an asset attribute value to something JSON-safe and displayable. */
function normalizeAttributeValue(value) {
  if (value === null || value === undefined) return null;
  const type = typeof value;
  if (type === 'string' || type === 'number' || type === 'boolean') return value;
  if (Array.isArray(value)) return value.map((item) => asText(item)).join(', ');
  try {
    return truncateText(JSON.stringify(value), REPORT_LIMITS.attributeValueChars);
  } catch {
    return truncateText(asText(value), REPORT_LIMITS.attributeValueChars);
  }
}

/**
 * Normalize the asset inventory and sort it deterministically (type order, then value).
 * @param {object[]} assets
 * @returns {object[]}
 */
export function normalizeAssets(assets) {
  return asArray(assets)
    .filter((asset) => asset && typeof asset === 'object')
    .map((asset) => {
      const attributes = asset.attributes && typeof asset.attributes === 'object' && !Array.isArray(asset.attributes) ? asset.attributes : {};
      return {
        id: asText(asset.id).trim(),
        type: pickEnum(asset.type, ASSET_TYPES, 'endpoint'),
        value: asText(asset.value).trim() || '(unknown)',
        parentId: asset.parentId == null ? null : asText(asset.parentId).trim() || null,
        state: asset.state === 'tested' ? 'tested' : 'untested',
        attributes: Object.fromEntries(
          Object.keys(attributes)
            .sort()
            .map((key) => [asText(key), normalizeAttributeValue(attributes[key])])
        ),
        firstSeen: normalizeDateIso(asset.firstSeen),
        lastSeen: normalizeDateIso(asset.lastSeen)
      };
    })
    .sort((a, b) => {
      const typeRank = ASSET_TYPES.indexOf(a.type) - ASSET_TYPES.indexOf(b.type);
      return typeRank !== 0 ? typeRank : a.value.localeCompare(b.value);
    });
}

/**
 * Recompute coverage from the full asset list. Percentages are integers and 0 when there are no
 * assets (never a misleading 100%).
 * @param {object[]} assets normalized assets
 * @returns {{byType: object, total: number, tested: number, untested: number, percentTested: number}}
 */
export function computeCoverage(assets) {
  const byType = {};
  for (const type of ASSET_TYPES) byType[type] = { total: 0, tested: 0, untested: 0 };
  for (const asset of assets) {
    const bucket = byType[asset.type] ?? (byType[asset.type] = { total: 0, tested: 0, untested: 0 });
    bucket.total += 1;
    if (asset.state === 'tested') bucket.tested += 1;
    else bucket.untested += 1;
  }
  const total = assets.length;
  const tested = assets.filter((asset) => asset.state === 'tested').length;
  return { byType, total, tested, untested: total - tested, percentTested: percent(tested, total) };
}

/** Normalize one run record, keeping stats and the per-module result lines but not module noise. */
function normalizeRun(raw) {
  const run = raw && typeof raw === 'object' ? raw : {};
  const stats = run.stats && typeof run.stats === 'object' ? run.stats : {};
  return {
    id: asText(run.id).trim() || '(unknown run)',
    status: asText(run.status).trim() || 'unknown',
    startedAt: normalizeDateIso(run.startedAt),
    endedAt: normalizeDateIso(run.endedAt),
    elapsedMs: Number.isFinite(Number(run.elapsedMs)) ? Number(run.elapsedMs) : null,
    mode: pickEnum(run.mode, MODES, null) ?? null,
    target: run.target == null ? null : asText(run.target),
    phases: asArray(run.phases).map((phase) => asText(phase)).filter(Boolean),
    stats: {
      modules: toCount(stats.modules),
      findings: toCount(stats.findings),
      assets: toCount(stats.assets),
      requests: toCount(stats.requests),
      denials: toCount(stats.denials),
      evidence: toCount(stats.evidence)
    },
    modules: asArray(run.modules)
      .filter((module) => module && typeof module === 'object')
      .map((module) => ({
        id: asText(module.id).trim(),
        phase: asText(module.phase).trim() || null,
        status: asText(module.status).trim() || 'unknown',
        ms: Number.isFinite(Number(module.ms)) ? Number(module.ms) : null,
        findings: toCount(module.findings),
        assets: toCount(module.assets),
        error: module.error ? truncateText(asText(module.error), 300) : null
      }))
  };
}

/**
 * Normalize runs, newest first.
 * @param {object[]} runs
 * @returns {object[]}
 */
export function normalizeRuns(runs) {
  return asArray(runs)
    .filter((run) => run && typeof run === 'object')
    .map(normalizeRun)
    .sort((a, b) => String(b.startedAt ?? '').localeCompare(String(a.startedAt ?? '')));
}

/**
 * Normalize the activity feed to `{ ts, message }` records in chronological order. Structured
 * debug payloads are intentionally dropped: the report does not need them.
 * @param {object[]} activity
 * @returns {object[]}
 */
export function normalizeActivity(activity) {
  return asArray(activity)
    .filter((entry) => entry && typeof entry === 'object')
    .map((entry) => ({
      ts: normalizeDateIso(entry.ts),
      message: truncateText(asText(entry.message), 500)
    }))
    .filter((entry) => entry.message);
}

/**
 * Normalize the audit summary block.
 * @param {object|null} audit
 * @returns {{total: number, allowed: number, denied: number, available: boolean}}
 */
export function normalizeAudit(audit) {
  if (!audit || typeof audit !== 'object') return { total: 0, allowed: 0, denied: 0, available: false };
  const total = toCount(audit.total);
  const allowed = toCount(audit.allowed);
  const denied = toCount(audit.denied);
  return { total, allowed, denied, available: true };
}

/** Human display of an asset's attributes object, e.g. `port=443, product=nginx`. */
export function formatAttributes(attributes) {
  const entries = Object.entries(attributes ?? {});
  if (entries.length === 0) return '—';
  return truncateText(
    entries
      .map(([key, value]) => `${key}=${value === null || value === undefined ? '' : asText(value)}`)
      .join(', '),
    300
  );
}

/** Display label for a run status. */
export function runStatusLabel(status) {
  return asText(status) || 'unknown';
}

/**
 * Fixed methodology description derived from the assessment mode. The wording is deliberately
 * precise: VANTAGE only performs non-destructive checks, and the report must say so.
 * @param {{scope: object, runs: object[], findings: object[]}} parts
 * @returns {{mode: string, capability: string, steps: object[], checks: string[]}}
 */
export function buildMethodology({ scope, runs, findings }) {
  const capabilities = {
    passive:
      'Passive mode: only DNS resolution and HTTP response-header inspection were permitted. No port ' +
      'scanning, TLS probing beyond a normal connection, or content discovery was performed.',
    safe:
      'Safe mode: the full non-destructive check set was enabled — DNS records, TLS configuration, TCP ' +
      'service identification, HTTP security configuration and bounded content discovery.',
    full:
      'Full mode: safe-mode checks plus the extended content-discovery list were enabled. Testing remained ' +
      'non-destructive.'
  };
  const checks = [...new Set(runs.flatMap((run) => run.modules.map((module) => module.id)).filter(Boolean))].sort();
  const steps = [
    {
      name: 'Scope enforcement',
      detail:
        'Every network action was authorized against the engagement scope before it ran. Out-of-scope or ' +
        'excluded requests were refused and recorded in the audit log rather than retried elsewhere.'
    },
    {
      name: 'Reconnaissance',
      detail:
        'DNS records, TLS configuration, exposed TCP services and (in scope) hostnames and endpoints were ' +
        'enumerated only for assets covered by the authorized scope.'
    },
    {
      name: 'Configuration review',
      detail:
        'Responses were graded against the enabled check set: HTTP security headers, cookie attributes, ' +
        'CORS policy, allowed methods and other non-destructive configuration signals.'
    },
    {
      name: 'Evidence capture',
      detail:
        'HTTP exchanges were stored as redacted, content-hashed evidence records. Findings reference those ' +
        'records by identifier; authorization headers, cookies and credential query parameters are redacted.'
    },
    {
      name: 'Analysis',
      detail:
        'Findings were normalized against a fixed severity, confidence and proof-of-evidence vocabulary. ' +
        'Re-observations merge into the existing finding instead of creating duplicates.'
    }
  ];
  return {
    mode: scope.mode,
    capability: capabilities[scope.mode] ?? capabilities.safe,
    steps,
    checks
  };
}

/**
 * Honest limitations, derived from what the snapshot actually contains.
 * @param {{engagement: object, scope: object, runs: object[], findings: object[], assets: object[], evidenceCount: number|null}} parts
 * @returns {string[]}
 */
export function buildLimitations({ engagement, scope, runs, findings, assets, evidenceCount }) {
  const limitations = [
    'Testing was non-destructive: no exploitation, brute force, fuzzing at volume, credential attack or ' +
      'denial-of-service activity was performed. The report therefore does not demonstrate exploitability.',
    'Results reflect the state of the systems at the time of testing. Services, configuration and code change, ' +
      'so findings should be re-validated before remediation is considered complete.',
    'Only assets explicitly covered by the authorized scope were tested. Any host, path or port outside that ' +
      'scope was not assessed and may hold undiscovered issues.',
    'Absence of a finding is not proof that a vulnerability is absent. The checks are bounded by the recorded ' +
      'scope, request budget, timeouts and the enabled check set.'
  ];
  if (scope.mode === 'passive') {
    limitations.push(
      'Passive mode was used, so active configuration checks and content discovery were limited; fewer findings ' +
        'than a safe-mode assessment would produce is expected.'
    );
  }
  if (runs.length === 0) {
    limitations.push(
      'No assessment run records were found in this engagement. Findings may have been recorded outside a ' +
        'recorded run, and run-level statistics are unavailable.'
    );
  }
  if (assets.length === 0) {
    limitations.push(
      'No assets were registered by the enabled checks, so coverage is reported as 0% rather than 100%. ' +
        'Coverage percentages are only meaningful once assets have been discovered.'
    );
  }
  if (!evidenceCount) {
    limitations.push(
      'No evidence records were available when the report was generated. Findings are reported from stored ' +
        'metadata, and supporting captures cannot be attached.'
    );
  }
  if (findings.some((finding) => finding.poe === 'observed' && finding.evidence.length === 0)) {
    limitations.push(
      'At least one finding is marked as observed but has no linked evidence record; treat those findings as ' +
        'lower-assurance observations.'
    );
  }
  if (findings.some((finding) => finding.status === 'accepted')) {
    limitations.push(
      'Accepted findings are client-acknowledged risks. They remain in the report for completeness and still ' +
        'contribute to the active risk rating.'
    );
  }
  if (engagement.endsAt && new Date(engagement.endsAt).getTime() < Date.now()) {
    limitations.push(
      `The authorization window ended at ${engagement.endsAt}; no testing may be performed beyond it without a ` +
        'new authorization.'
    );
  }
  return limitations;
}
