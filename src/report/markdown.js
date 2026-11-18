/**
 * GitHub-flavoured Markdown report builder (with table of contents).
 *
 * Renders from the normalized JSON object produced by `buildJsonReport`, so ordering, counts and
 * vocabulary are identical to the JSON and HTML deliverables. Every target-controlled string is
 * escaped: raw HTML is neutralised and GFM syntax characters are backslash-escaped.
 */
import { formatBytes, percent } from '../core/util.js';
import { buildJsonReport } from './json.js';
import {
  REPORT_DISCLAIMER,
  REPORT_LIMITS,
  REPORT_SCHEMA_VERSION,
  SEVERITY_ORDER,
  SEVERITY_META,
  STATUS_META,
  VANTAGE_VERSION,
  countLabel,
  escapeMarkdownCell,
  escapeMarkdownInline,
  formatAttributes,
  formatDate,
  formatDuration,
  severityLabel,
  truncateText
} from './shared.js';

const SECTIONS = Object.freeze([
  ['Executive summary', 'executive-summary'],
  ['Severity summary', 'severity-summary'],
  ['Status summary', 'status-summary'],
  ['Scope and methodology', 'scope-and-methodology'],
  ['Findings', 'findings'],
  ['Coverage', 'coverage'],
  ['Asset inventory', 'asset-inventory'],
  ['Assessment runs', 'assessment-runs'],
  ['Audit summary', 'audit-summary'],
  ['Limitations', 'limitations'],
  ['Disclaimer', 'disclaimer']
]);

const LIMIT_LABELS = Object.freeze({
  requestsPerSecond: ['Global request rate', 'req/s'],
  perHostRequestsPerSecond: ['Per-host request rate', 'req/s'],
  concurrency: ['Concurrency', 'requests'],
  maxRequests: ['Request budget', 'requests'],
  timeoutMs: ['Request timeout', 'ms'],
  maxResponseBytes: ['Max response size', 'bytes'],
  maxEvidenceBytes: ['Max evidence capture size', 'bytes']
});

/** Wrap text in a code span, stripping backticks so the span cannot be broken. */
function codeSpan(value) {
  const text = String(value ?? '').replace(/[`\r\n]/g, '');
  return `\`${text}\``;
}

/** Build a GFM table from escaped header labels and cell values. */
function table(headers, rows, aligns = []) {
  const separator = headers.map((_, index) => (aligns[index] === 'right' ? '---:' : '---'));
  const lines = [
    `| ${headers.join(' | ')} |`,
    `| ${separator.join(' | ')} |`,
    ...rows.map((row) => `| ${row.join(' | ')} |`)
  ];
  return lines.join('\n');
}

/** Human duration for a run phase, preferring the run-level elapsed time. */
function runDuration(run) {
  if (run.elapsedMs != null) return formatDuration(run.elapsedMs);
  const started = run.startedAt ? new Date(run.startedAt).getTime() : null;
  const ended = run.endedAt ? new Date(run.endedAt).getTime() : null;
  if (started != null && ended != null && ended >= started) return formatDuration(ended - started);
  return '—';
}

/** Render free prose: escape, split on blank lines into paragraphs. */
function prose(text, fallback = '_Not recorded._') {
  const value = String(text ?? '').trim();
  if (!value) return fallback;
  return value
    .split(/\n{2,}/)
    .map((paragraph) => escapeMarkdownInline(paragraph.trim()))
    .join('\n\n');
}

/** Join a list of items as escaped Markdown bullets. */
function bullets(items) {
  return items.map((item) => `- ${escapeMarkdownInline(item)}`).join('\n');
}

/** Build the title/metadata block. */
function renderHeader(report) {
  const engagement = report.engagement;
  const rows = [
    ['Client', engagement.client || '—'],
    ['Engagement', codeSpan(engagement.id)],
    ['Assessment mode', codeSpan(report.scope.mode)],
    ['Authorization reference', engagement.authorizationRef ? `**${escapeMarkdownCell(engagement.authorizationRef)}**` : '_Not recorded_'],
    ['Authorized by', engagement.authorizedBy || '—'],
    ['Assessment window', `${formatDate(engagement.startsAt)} → ${formatDate(engagement.endsAt)}`],
    ['Report generated', formatDate(report.generatedAt)],
    ['Report schema', `\`${report.schemaVersion}\` (tool VANTAGE ${VANTAGE_VERSION})`]
  ];
  return [
    `# ${escapeMarkdownInline(engagement.name)} — Security Assessment Report`,
    '',
    table(['Field', 'Value'], rows.map((row) => [escapeMarkdownCell(row[0]), escapeMarkdownCell(row[1])]))
  ];
}

/** Authorization and handling notice that must precede the technical content. */
function renderAuthorization(report) {
  const engagement = report.engagement;
  const reference = engagement.authorizationRef
    ? `**${escapeMarkdownInline(engagement.authorizationRef)}**`
    : 'the authorization reference recorded by the engagement owner';
  const authorizedBy = engagement.authorizedBy ? ` by **${escapeMarkdownInline(engagement.authorizedBy)}**` : '';
  return [
    '## Authorization notice',
    '',
    `> This report describes a **non-destructive** security assessment of assets authorized in writing ` +
      `under ${reference}${authorizedBy}. Testing was limited to the assets, time window and check set recorded ` +
      `in this engagement. VANTAGE performs no exploitation, no brute force, no fuzzing at volume and no ` +
      `denial-of-service testing. Do not act on this report outside the recorded authorization.`
  ];
}

/** Table of contents with GFM anchors matching the section headings below. */
function renderToc() {
  return [
    '## Table of contents',
    '',
    ...SECTIONS.map(([title, anchor], index) => `${index + 1}. [${title}](#${anchor})`)
  ];
}

/** Executive summary: risk rating, scope of work, active findings and status mix. */
function renderExecutiveSummary(report) {
  const { summary, engagement, coverage } = report;
  const lines = ['## Executive summary', ''];
  lines.push(`**Overall risk rating: ${summary.riskLabel}** (active risk score ${summary.active.riskScore}).`, '');
  lines.push(
    `VANTAGE performed a non-destructive security assessment of **${escapeMarkdownInline(engagement.name)}**` +
      `${engagement.client ? ` for **${escapeMarkdownInline(engagement.client)}**` : ''} across ` +
      `${countLabel(report.scope.targets.length, 'authorized target')} in \`${report.scope.mode}\` mode.`
  );

  if (report.runs.length === 0) {
    lines.push(
      '',
      'No assessment runs are recorded in this engagement; the findings below were recorded outside a recorded run.'
    );
  } else {
    lines.push(
      '',
      `${countLabel(report.runs.length, 'assessment run')} ${report.runs.length === 1 ? 'is' : 'are'} recorded. ` +
        `Together they produced ${countLabel(summary.total, 'finding')} across ` +
        `${countLabel(coverage.total, 'asset')} (${coverage.tested} tested, ${coverage.untested} untested).`
    );
  }

  if (summary.total > 0) {
    const closed = summary.total - summary.active.total;
    lines.push(
      '',
      `${countLabel(summary.active.total, 'finding')} ${summary.active.total === 1 ? 'remains' : 'remain'} active; ` +
        `${closed} ${closed === 1 ? 'is' : 'are'} closed as fixed or false positive. ` +
        `Active by severity: critical ${summary.active.bySeverity.critical}, ` +
        `high ${summary.active.bySeverity.high}, medium ${summary.active.bySeverity.medium}, ` +
        `low ${summary.active.bySeverity.low}, info ${summary.active.bySeverity.info}. ` +
        `The rating follows from these active counts and the weighted risk score, not from closed findings.`
    );
    const top = report.findings.find((finding) => finding.status !== 'fixed' && finding.status !== 'false_positive');
    if (top) {
      lines.push(
        '',
        `The highest-severity active finding is **${escapeMarkdownInline(top.title)}** ` +
          `(${severityLabel(top.severity).toUpperCase()}) at \`${escapeMarkdownInline(top.target)}\`.`
      );
    }
    lines.push(
      '',
      'Remediation should follow severity order, starting with critical and high findings. Re-testing after ' +
        'remediation is recommended to confirm each finding no longer reproduces.'
    );
  } else {
    lines.push(
      '',
      '**No findings observed.** The enabled checks did not detect the issues they target within the authorized ' +
        'scope at the time of testing. This is not evidence that the systems are free of vulnerabilities: coverage ' +
        'is limited to the scope and check set recorded below, and systems change over time. Treat this result as ' +
        'a clean baseline rather than a guarantee.'
    );
  }
  return lines;
}

/** Severity distribution table. */
function renderSeveritySummary(report) {
  const { summary } = report;
  const rows = SEVERITY_ORDER.map((severity) => [
    `**${SEVERITY_META[severity].label}**`,
    String(summary.bySeverity[severity] ?? 0),
    `${percent(summary.bySeverity[severity] ?? 0, summary.total)}%`
  ]);
  rows.push(['**Total**', `**${summary.total}**`, `${summary.total > 0 ? 100 : 0}%`]);
  return [
    '## Severity summary',
    '',
    table(['Severity', 'Findings', 'Share'], rows, ['left', 'right', 'right']),
    '',
    '_Shares are rounded. The risk rating is derived from active findings (all statuses except fixed and ' +
      'false positive) using the severity weights critical 10, high 6, medium 3, low 1, info 0._'
  ];
}

/** Lifecycle status distribution table. */
function renderStatusSummary(report) {
  const { summary } = report;
  const rows = Object.entries(STATUS_META).map(([status, meta]) => [meta.label, String(summary.byStatus[status] ?? 0)]);
  rows.push(['**Total**', `**${summary.total}**`]);
  return ['## Status summary', '', table(['Status', 'Findings'], rows, ['left', 'right'])];
}

/** Authorized scope plus methodology description. */
function renderScopeAndMethodology(report) {
  const { scope, methodology } = report;
  const lines = ['## Scope and methodology', '', '### Authorized scope', ''];
  lines.push(`- **Assessment mode:** \`${scope.mode}\``);
  if (scope.targets.length) {
    lines.push('- **Authorized targets:**');
    for (const target of scope.targets) lines.push(`  - \`${escapeMarkdownInline(target)}\``);
  } else {
    lines.push('- **Authorized targets:** _none recorded_');
  }
  if (scope.exclude.length) {
    lines.push('- **Exclusions:**');
    for (const entry of scope.exclude) lines.push(`  - \`${escapeMarkdownInline(entry)}\``);
  } else {
    lines.push('- **Exclusions:** none');
  }
  const portsText =
    scope.ports.include.length || scope.ports.exclude.length
      ? `include ${scope.ports.include.length ? scope.ports.include.join(', ') : 'any'}; exclude ${
          scope.ports.exclude.length ? scope.ports.exclude.join(', ') : 'none'
        }`
      : 'any port not excluded by policy';
  lines.push(`- **Port rules:** ${portsText}`);
  const limitEntries = Object.entries(scope.limits);
  if (limitEntries.length) {
    const rendered = limitEntries.map(([key, value]) => {
      const [label, unit] = LIMIT_LABELS[key] ?? [key, ''];
      const shown = unit === 'bytes' ? formatBytes(value) : unit === 'ms' ? `${value} ms` : String(value);
      return `${label.toLowerCase()} ${shown}`;
    });
    lines.push(`- **Rate limits and budgets:** ${rendered.join('; ')}`);
  } else {
    lines.push('- **Rate limits and budgets:** not recorded');
  }
  lines.push(`- **Third-party endpoints:** ${scope.allowThirdParty ? 'permitted' : 'not permitted'}`);

  lines.push('', '### Methodology', '', escapeMarkdownInline(methodology.capability), '');
  methodology.steps.forEach((step, index) => {
    lines.push(`${index + 1}. **${escapeMarkdownInline(step.name)}** — ${escapeMarkdownInline(step.detail)}`);
  });
  lines.push('');
  if (methodology.checks.length) {
    lines.push(
      `**Checks executed (${methodology.checks.length}):** ${methodology.checks.map((id) => codeSpan(id)).join(', ')}`
    );
  } else {
    lines.push('**Checks executed:** _No module execution records were available, so the executed check set could not be reconstructed._');
  }
  lines.push(
    '',
    'Every network action was authorized through the scope guard. Refusals are recorded in the audit trail, and ' +
      'evidence records are redacted for secrets and truncated to a bounded preview.'
  );
  return lines;
}

/** One finding's detail block. */
function renderFinding(finding, index) {
  const lines = [];
  lines.push(
    `### Finding ${index}: ${escapeMarkdownInline(finding.title)}`,
    '',
    `**Severity: ${severityLabel(finding.severity).toUpperCase()}** · **Confidence:** ` +
      `\`${finding.confidence}\` · **Status:** \`${finding.status}\` · **Proof of evidence:** \`${finding.poe}\``,
    ''
  );
  const attributes = [
    ['Target', escapeMarkdownCell(finding.target)],
    ['Check', codeSpan(finding.check)],
    ['Finding id', finding.id ? codeSpan(finding.id) : '—'],
    ['First observed', formatDate(finding.firstSeen)],
    ['Last observed', formatDate(finding.lastSeen)],
    ['Occurrences', String(finding.occurrences)],
    ['CWE', finding.cwe.length ? finding.cwe.map((value) => escapeMarkdownCell(value)).join(', ') : '—'],
    ['OWASP', finding.owasp.length ? finding.owasp.map((value) => escapeMarkdownCell(value)).join(', ') : '—']
  ];
  lines.push(table(['Attribute', 'Value'], attributes.map(([key, value]) => [key, value])), '');

  lines.push('**Description**', '', prose(finding.description), '');
  lines.push('**Impact**', '', prose(finding.impact, '_Not described by the check._'), '');
  lines.push('**Remediation**', '', prose(finding.remediation, '_No remediation guidance was provided by the check._'), '');

  lines.push('**Observed**', '');
  if (finding.observed.length) {
    const rows = finding.observed.map((item) => [
      escapeMarkdownCell(truncateText(item.key, 200)) || '—',
      escapeMarkdownCell(truncateText(item.value, 300)) || '—'
    ]);
    lines.push(table(['Key', 'Value'], rows), '');
  } else {
    lines.push('_No observed values were captured for this finding._', '');
  }

  lines.push('**Evidence**', '');
  if (finding.evidence.length) {
    lines.push(...finding.evidence.map((id) => `- ${codeSpan(id)}`), '');
  } else {
    lines.push('_No evidence identifiers were recorded._', '');
  }

  if (finding.references.length) {
    lines.push('**References**', '');
    for (const reference of finding.references) {
      lines.push(`- ${escapeMarkdownInline(reference)}`);
    }
    lines.push('');
  }
  return lines;
}

/** Findings section, including the honest zero-finding state. */
function renderFindings(report) {
  const lines = ['## Findings', ''];
  if (report.findings.length === 0) {
    lines.push(
      '**No findings observed.** No finding was recorded in this engagement snapshot. The enabled checks did not ' +
        'detect the issues they target, but this result only covers the scope and check set recorded above. ' +
        'Re-test after any change to the assessed systems, and do not interpret the empty result as proof that ' +
        'no vulnerabilities exist.',
      '',
      `No gaps in coverage are hidden by this result: ${countLabel(report.coverage.total, 'asset')} were recorded ` +
        `and ${report.coverage.tested} of them were tested (${report.coverage.percentTested}%).`
    );
    return lines;
  }
  lines.push(
    `Findings are ordered by severity (critical first) and then by title. ${countLabel(
      report.findings.length,
      'finding'
    )} recorded; ${report.summary.active.total} currently active.`,
    ''
  );
  report.findings.forEach((finding, index) => {
    lines.push(...renderFinding(finding, index + 1), '');
  });
  return lines;
}

/** Coverage table and explanation. */
function renderCoverage(report) {
  const { coverage } = report;
  const rows = [
    ...Object.entries(coverage.byType).map(([type, bucket]) => [
      type,
      String(bucket.total),
      String(bucket.tested),
      String(bucket.untested),
      `${percent(bucket.tested, bucket.total)}%`
    ]),
    ['**Total**', `**${coverage.total}**`, `**${coverage.tested}**`, `**${coverage.untested}**`, `**${coverage.percentTested}%**`]
  ];
  const lines = [
    '## Coverage',
    '',
    'Coverage counts the assets registered by the checks and whether each one was tested. Untested assets are a ' +
      'known gap, not a clean result.',
    '',
    table(['Asset type', 'Total', 'Tested', 'Untested', 'Tested %'], rows, ['left', 'right', 'right', 'right', 'right']),
    ''
  ];
  if (coverage.total === 0) {
    lines.push('_No assets were recorded, so coverage is reported as 0% rather than 100%._');
  } else if (coverage.untested > 0) {
    lines.push(
      `_${countLabel(coverage.untested, 'asset')} remained untested (${100 - coverage.percentTested}% of the ` +
        'inventory). Findings should be read with that gap in mind._'
    );
  } else {
    lines.push('_Every recorded asset was tested at least once._');
  }
  return lines;
}

/** Asset inventory table, capped for readability. */
function renderAssets(report) {
  const lines = ['## Asset inventory', ''];
  if (report.assets.length === 0) {
    lines.push('_No assets were recorded._');
    return lines;
  }
  const rows = report.assets
    .slice(0, REPORT_LIMITS.markdownAssets)
    .map((asset, index) => [
      String(index + 1),
      escapeMarkdownCell(asset.type),
      `\`${escapeMarkdownInline(asset.value)}\``,
      escapeMarkdownCell(asset.state),
      escapeMarkdownCell(formatAttributes(asset.attributes))
    ]);
  lines.push(
    table(['#', 'Type', 'Value', 'State', 'Attributes'], rows, ['right', 'left', 'left', 'left', 'left']),
    '',
    `_${countLabel(report.assetsTotal, 'asset')} recorded; showing the first ${Math.min(
      report.assets.length,
      REPORT_LIMITS.markdownAssets
    )}. The JSON report contains up to ${REPORT_LIMITS.jsonAssets}._`
  );
  return lines;
}

/** Assessment run history. */
function renderRuns(report) {
  const lines = ['## Assessment runs', ''];
  if (report.runs.length === 0) {
    lines.push('_No assessment runs recorded._');
    return lines;
  }
  const rows = report.runs.map((run) => [
    codeSpan(run.id),
    escapeMarkdownCell(run.status),
    formatDate(run.startedAt),
    runDuration(run),
    String(run.stats.modules),
    String(run.stats.findings),
    String(run.stats.requests),
    String(run.stats.denials)
  ]);
  lines.push(
    table(
      ['Run', 'Status', 'Started', 'Duration', 'Modules', 'Findings', 'Requests', 'Denials'],
      rows,
      ['left', 'left', 'left', 'right', 'right', 'right', 'right', 'right']
    )
  );
  return lines;
}

/** Audit-trail summary: what was allowed and what was refused. */
function renderAudit(report) {
  const { audit } = report;
  const lines = ['## Audit summary', ''];
  if (!audit.available) {
    lines.push('_Audit data was not available when the report was generated._');
    return lines;
  }
  lines.push(
    table(
      ['Metric', 'Count'],
      [
        ['Network decisions recorded', String(audit.total)],
        ['Allowed', String(audit.allowed)],
        ['Denied by scope enforcement', String(audit.denied)],
        ['Evidence records', String(report.evidenceCount)]
      ],
      ['left', 'right']
    ),
    '',
    '_A denied decision means the scope guard refused the action; it was not retried elsewhere._'
  );
  return lines;
}

/** Limitations and disclaimer tail. */
function renderTail(report) {
  const lines = ['## Limitations', ''];
  if (report.limitations.length) {
    lines.push(bullets(report.limitations));
  } else {
    lines.push('- No specific limitations were recorded.');
  }
  lines.push('', '## Disclaimer', '', escapeMarkdownInline(REPORT_DISCLAIMER), '');
  lines.push(
    `_Report generated by VANTAGE ${VANTAGE_VERSION} (schema ${REPORT_SCHEMA_VERSION}) at ` +
      `${formatDate(report.generatedAt)}._`
  );
  return lines;
}

/**
 * Build the full Markdown report.
 * @param {object} snapshot engagement snapshot (or plain fixture with the same shape)
 * @returns {string} GitHub-flavoured Markdown document
 */
export function buildMarkdownReport(snapshot) {
  const report = buildJsonReport(snapshot);
  const lines = [];
  const section = (rendered) => {
    if (lines.length && lines[lines.length - 1] !== '') lines.push('');
    lines.push(...rendered);
  };
  section(renderHeader(report));
  section(renderAuthorization(report));
  section(renderToc());
  section(renderExecutiveSummary(report));
  section(renderSeveritySummary(report));
  section(renderStatusSummary(report));
  section(renderScopeAndMethodology(report));
  section(renderFindings(report));
  section(renderCoverage(report));
  section(renderAssets(report));
  section(renderRuns(report));
  section(renderAudit(report));
  section(renderTail(report));

  return `${lines.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd()}\n`;
}
