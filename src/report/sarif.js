/**
 * SARIF 2.1.0 export, the interchange format read by DefectDojo, GitHub code scanning and most
 * vulnerability management tools. One rule per check id, one result per finding.
 */
import { VANTAGE_VERSION } from './shared.js';

const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };
// GitHub's "security-severity" scale (0-10) drives its critical/high/medium/low badges.
const SCORE = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };

/**
 * @param {object} report output of buildJsonReport
 * @returns {object} SARIF log
 */
export function buildSarif(report) {
  const active = report.findings.filter((f) => f.status !== 'fixed' && f.status !== 'false_positive');
  const rules = new Map();
  for (const f of active) {
    if (rules.has(f.check)) continue;
    rules.set(f.check, {
      id: f.check,
      name: f.check.replace(/[^a-zA-Z0-9]+(.)/g, (_, c) => c.toUpperCase()),
      shortDescription: { text: f.title },
      fullDescription: { text: f.description || f.title },
      help: { text: f.remediation || 'See the VANTAGE report.' },
      ...(f.references[0] ? { helpUri: f.references[0] } : {}),
      properties: { tags: ['security', ...f.cwe, ...f.owasp], 'security-severity': SCORE[f.severity] ?? '0.0' }
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'VANTAGE', version: VANTAGE_VERSION, informationUri: 'https://github.com/sanjeldarshan65-afk/vantage', rules: [...rules.values()] } },
      results: active.map((f) => ({
        ruleId: f.check,
        level: LEVEL[f.severity] ?? 'note',
        message: { text: `${f.title}. ${f.remediation}`.trim() },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.target } } }],
        partialFingerprints: { vantageFinding: f.id || `${f.check}|${f.target}` },
        properties: { severity: f.severity, confidence: f.confidence, status: f.status, evidence: f.evidence }
      }))
    }]
  };
}
