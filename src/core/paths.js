import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path of the `vantage/` directory. */
export const VANTAGE_ROOT = path.resolve(here, '..', '..');

/** Directory holding engagement data. Override with VANTAGE_DATA_DIR. */
export function dataDir() {
  return process.env.VANTAGE_DATA_DIR
    ? path.resolve(process.env.VANTAGE_DATA_DIR)
    : path.join(VANTAGE_ROOT, 'data');
}

/** Directory holding every engagement. */
export function engagementsDir() {
  return path.join(dataDir(), 'engagements');
}

/** Directory of one engagement. */
export function engagementDir(id) {
  return path.join(engagementsDir(), id);
}

/** File names inside an engagement directory. */
export const FILES = Object.freeze({
  engagement: 'engagement.json',
  audit: 'audit.jsonl',
  evidence: 'evidence.jsonl',
  findings: 'findings.json',
  assets: 'assets.json',
  activity: 'activity.jsonl',
  runs: 'runs',
  reports: 'reports'
});

/** Resolve a file inside one engagement directory. */
export function engagementFile(id, name) {
  return path.join(engagementDir(id), name);
}

/** Validate an engagement id (also used as a directory name). */
export function isValidEngagementId(id) {
  return typeof id === 'string' && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(id);
}
