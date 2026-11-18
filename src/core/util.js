import { createHash, randomBytes } from 'node:crypto';
import { isIP } from 'node:net';
import { promises as fs } from 'node:fs';
import path from 'node:path';

const ID_ALPHABET = '0123456789abcdef';

/** Short random hex id with a type prefix, e.g. `fnd_1a2b3c4d5e6f`. */
export function newId(prefix, bytes = 6) {
  const raw = randomBytes(bytes);
  let out = '';
  for (const byte of raw) out += ID_ALPHABET[byte & 0x0f] + ID_ALPHABET[byte >> 4];
  return `${prefix}_${out.slice(0, bytes * 2)}`;
}

/** sha256 hex digest of a string or Buffer. */
export function sha256(input) {
  return createHash('sha256').update(input).digest('hex');
}

/** Short stable hash (12 hex chars) used for dedupe keys. */
export function shortHash(input, length = 12) {
  return sha256(input).slice(0, length);
}

/** ISO timestamp for the current instant. */
export function nowIso() {
  return new Date().toISOString();
}

/** @returns {Promise<void>} */
export function sleep(ms, signal) {
  if (ms <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

/** Clamp a number into [min, max]. */
export function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

/** Normalize a hostname for comparisons: lowercase, strip brackets and a trailing dot. */
export function normalizeHost(host) {
  if (!host) return '';
  let value = String(host).trim().toLowerCase();
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);
  while (value.endsWith('.')) value = value.slice(0, -1);
  return value;
}

/** Parse `host:port`, `[v6]:port`, a URL, or a bare host into parts. */
export function parseHostPort(input) {
  const text = String(input || '').trim();
  if (!text) return { host: '', port: null };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) {
    const url = new URL(text);
    const scheme = url.protocol.replace(':', '');
    const port = url.port ? Number(url.port) : defaultPort(scheme);
    return { host: normalizeHost(url.hostname), port, scheme, url };
  }
  if (text.startsWith('[')) {
    const end = text.indexOf(']');
    const host = text.slice(1, end);
    const rest = text.slice(end + 1);
    return { host: normalizeHost(host), port: rest.startsWith(':') ? Number(rest.slice(1)) : null };
  }
  const colon = text.lastIndexOf(':');
  if (colon > -1 && text.indexOf(':') === colon) {
    const maybePort = text.slice(colon + 1);
    if (/^\d{1,5}$/.test(maybePort)) return { host: normalizeHost(text.slice(0, colon)), port: Number(maybePort) };
  }
  return { host: normalizeHost(text), port: null };
}

/** Default port for a scheme. */
export function defaultPort(scheme) {
  return scheme === 'https' ? 443 : scheme === 'http' ? 80 : null;
}

/** Expand an IPv6 address into 8 groups of 16 bits. */
export function ipv6Groups(ip) {
  let text = ip.toLowerCase();
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  const lastColon = text.lastIndexOf(':');
  const tail = text.slice(lastColon + 1);
  if (tail.includes('.')) {
    const [a, b, c, d] = tail.split('.').map(Number);
    text = `${text.slice(0, lastColon + 1)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, rest] = text.split('::');
  const left = head ? head.split(':').filter(Boolean) : [];
  const right = rest === undefined ? [] : rest.split(':').filter(Boolean);
  const missing = 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(0, missing)).fill('0'), ...right];
  return groups.slice(0, 8).map((g) => parseInt(g, 16));
}

/** Convert an IPv4/IPv6 literal to a BigInt (or null when invalid). */
export function ipToBigInt(ip) {
  const family = isIP(normalizeHost(ip));
  if (family === 4) {
    return normalizeHost(ip).split('.').reduce((acc, octet) => (acc << 8n) + BigInt(Number(octet)), 0n);
  }
  if (family === 6) {
    return ipv6Groups(ip).reduce((acc, group) => (acc << 16n) + BigInt(group), 0n);
  }
  return null;
}

/** Bit length of a full address for the family (32 or 128). */
export function ipBits(ip) {
  const family = isIP(ip);
  return family === 4 ? 32 : family === 6 ? 128 : null;
}

/** Parse `addr/bits` into a numeric range, or null when invalid. */
export function parseCidr(cidr) {
  const [addr, bitsText] = String(cidr).split('/');
  if (bitsText === undefined) return null;
  const family = isIP(addr);
  if (!family) return null;
  const bits = Number(bitsText);
  const total = family === 4 ? 32 : 128;
  if (!Number.isInteger(bits) || bits < 0 || bits > total) return null;
  const value = ipToBigInt(addr);
  const hostBits = BigInt(total - bits);
  const network = (value >> hostBits) << hostBits;
  const last = network + (1n << hostBits) - 1n;
  return { family, bits, network, last, total, cidr: `${addr}/${bits}` };
}

/** True when `ip` is inside the parsed CIDR range. */
export function cidrContains(cidr, ip) {
  const range = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  const value = ipToBigInt(ip);
  if (!range || value === null) return false;
  if (ipBits(ip) !== range.total) return false;
  return value >= range.network && value <= range.last;
}

/** True for loopback / private / link-local / reserved ranges (used for safety hints). */
export function isPrivateAddress(ip) {
  const value = ipToBigInt(ip);
  if (value === null) return false;
  const family = isIP(ip);
  if (family === 4) {
    const ranges = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8', '169.254.0.0/16', '100.64.0.0/10', '0.0.0.0/8'];
    return ranges.some((cidr) => cidrContains(cidr, ip));
  }
  if (family === 6) {
    return ip === '::1' || ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd') || ip.toLowerCase().startsWith('fe80');
  }
  return false;
}

/** Header names whose values must never be stored in evidence. */
const SECRET_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'api-key', 'x-auth-token']);
const SECRET_QUERY = /^(token|key|api[_-]?key|secret|password|passwd|pwd|session|sessionid|auth|sig|signature|access_token|id_token)$/i;

/** Redact secret request headers (case-insensitive) while keeping the header names. */
export function redactHeaders(headers, { keepCookies = false } = {}) {
  /** @type {Record<string,string>} */
  const out = {};
  for (const [name, value] of Object.entries(headers || {})) {
    const lower = name.toLowerCase();
    if (lower === 'set-cookie' && keepCookies) { out[name] = value; continue; }
    if (SECRET_HEADERS.has(lower)) {
      out[name] = '<redacted>';
      continue;
    }
    out[name] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return out;
}

/** Redact credential-looking query parameters from a URL string. */
export function redactUrl(url) {
  try {
    const parsed = new URL(url);
    for (const key of [...parsed.searchParams.keys()]) {
      if (SECRET_QUERY.test(key)) parsed.searchParams.set(key, '<redacted>');
    }
    if (parsed.password) parsed.password = '<redacted>';
    return parsed.toString();
  } catch {
    return String(url);
  }
}

/** Shorten text for human display. */
export function truncate(text, max = 120) {
  const value = String(text ?? '');
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

/** Sort findings by severity descending. */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

/** Numeric rank of a severity (0 = critical). */
export function severityRank(severity) {
  const index = SEVERITY_ORDER.indexOf(severity);
  return index === -1 ? SEVERITY_ORDER.length : index;
}

/** Human byte formatting. */
export function formatBytes(bytes) {
  const n = Number(bytes) || 0;
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

/** Ensure a directory exists. */
export async function ensureDir(dir) {
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

/** Read and parse JSON, returning `fallback` when the file is missing. */
export async function readJson(file, fallback = null) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    if (error?.code === 'ENOENT') return fallback;
    throw error;
  }
}

/** Atomically write JSON (write temp file, then rename). */
export async function writeJsonAtomic(file, value) {
  await ensureDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  await fs.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await fs.rename(tmp, file);
  return file;
}

/** Append one JSON line to a `.jsonl` file. */
export async function appendJsonl(file, record) {
  await ensureDir(path.dirname(file));
  await fs.appendFile(file, `${JSON.stringify(record)}\n`, 'utf8');
  return file;
}

/** Read a `.jsonl` file into an array, tolerating a trailing partial line. */
export async function readJsonl(file) {
  let text;
  try {
    text = await fs.readFile(file, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const rows = [];
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      rows.push(JSON.parse(trimmed));
    } catch {
      // A process may have been killed mid-write; skip the incomplete line.
    }
  }
  return rows;
}

/** Count lines of a file without loading it. */
export async function countLines(file) {
  try {
    const text = await fs.readFile(file, 'utf8');
    return text.split('\n').filter(Boolean).length;
  } catch {
    return 0;
  }
}

/** Percent helper that never divides by zero. */
export function percent(part, total) {
  if (!total) return 0;
  return Math.round((part / total) * 100);
}
