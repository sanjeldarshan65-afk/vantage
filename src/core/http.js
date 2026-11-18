import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import { X509Certificate } from 'node:crypto';
import { NetworkError } from './errors.js';
import { formatBytes } from './util.js';

const DEFAULT_UA = 'Vantage/0.1 (authorized security assessment; +https://github.com/BaaRai/ARTEX inspired)';

/** Keep-alive agents, one per protocol; TLS verification on unless a caller opts out. */
const agents = {
  'http:': new http.Agent({ keepAlive: true, maxSockets: 8, timeout: 30000 }),
  'https:': new https.Agent({ keepAlive: true, maxSockets: 8, timeout: 30000 }),
  'https-insecure': new https.Agent({ keepAlive: true, maxSockets: 8, timeout: 30000, rejectUnauthorized: false })
};

/** Close pooled sockets (called on CLI exit / server stop). */
export function closeAgents() {
  for (const agent of Object.values(agents)) agent.destroy();
}

function getHeader(headers, name) {
  const value = headers?.[name.toLowerCase()];
  if (Array.isArray(value)) return value[0] ?? null;
  return value ?? null;
}

/** Decode a response body according to Content-Encoding, returning input on failure. */
function decodeBody(raw, encoding) {
  const value = String(encoding ?? '').toLowerCase().trim();
  if (!value || value === 'identity' || raw.length === 0) return raw;
  try {
    if (value === 'gzip' || value === 'x-gzip') return zlib.gunzipSync(raw);
    if (value === 'deflate') {
      try {
        return zlib.inflateSync(raw);
      } catch {
        return zlib.inflateRawSync(raw);
      }
    }
    if (value === 'br') return zlib.brotliDecompressSync(raw);
  } catch {
    return raw;
  }
  return raw;
}

/** Turn the peer certificate into a plain, serializable analysis object. */
function describeCertificate(socket, host) {
  if (!socket) return null;
  let der;
  try {
    const peer = socket.getPeerCertificate?.(true);
    der = peer?.raw ?? null;
  } catch {
    der = null;
  }
  const tls = {
    protocol: null,
    servername: host,
    cipher: null,
    authorized: null,
    authorizationError: null,
    cert: null
  };
  try {
    tls.protocol = socket.getProtocol?.() ?? null;
    const cipher = socket.getCipher?.();
    tls.cipher = cipher ? { name: cipher.name, version: cipher.version } : null;
    tls.authorized = typeof socket.authorized === 'boolean' ? socket.authorized : null;
    tls.authorizationError = socket.authorizationError ? String(socket.authorizationError) : null;
  } catch {
    /* best effort */
  }
  if (!der) return tls;
  try {
    const x509 = new X509Certificate(der);
    const key = x509.publicKey;
    const details = key?.asymmetricKeyDetails ?? {};
    tls.cert = {
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: toIso(x509.validFromDate, x509.validFrom),
      validTo: toIso(x509.validToDate, x509.validTo),
      serialNumber: x509.serialNumber,
      fingerprint256: x509.fingerprint256,
      subjectAltName: x509.subjectAltName ?? '',
      keyType: key?.asymmetricKeyType ?? null,
      keyBits: details.modulusLength ?? details.namedCurve ?? null,
      selfSigned: x509.subject === x509.issuer,
      isCA: Boolean(x509.ca),
      hostnameMatch: host ? Boolean(x509.checkHost(host, { wildcards: true })) : null
    };
  } catch {
    /* certificate parsing is best-effort; protocol/cipher may still be usable */
  }
  return tls;
}

function toIso(dateValue, textValue) {
  if (dateValue instanceof Date && !Number.isNaN(dateValue.getTime())) return dateValue.toISOString();
  if (textValue) {
    const parsed = new Date(textValue);
    if (!Number.isNaN(parsed.getTime())) return parsed.toISOString();
  }
  return null;
}

/**
 * Perform exactly one HTTP exchange (no redirect following — the guard re-checks scope per hop).
 *
 * @param {string} url absolute http(s) URL
 * @param {{
 *   method?: string, headers?: Record<string,string>, body?: string|Buffer|null,
 *   timeoutMs?: number, maxBytes?: number, signal?: AbortSignal,
 *   rejectUnauthorized?: boolean, userAgent?: string
 * }} [options]
 * @returns {Promise<object>} response summary
 */
export async function requestOnce(url, options = {}) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new NetworkError(`Unsupported protocol ${parsed.protocol} for ${url}`, { url });
  }
  const isHttps = parsed.protocol === 'https:';
  const rejectUnauthorized = options.rejectUnauthorized !== false;
  const timeoutMs = options.timeoutMs ?? 8000;
  const maxBytes = options.maxBytes ?? 262144;
  const method = (options.method ?? 'GET').toUpperCase();
  const headers = {
    'user-agent': options.userAgent ?? DEFAULT_UA,
    accept: '*/*',
    'accept-encoding': 'gzip, deflate, br',
    connection: 'close',
    ...Object.fromEntries(Object.entries(options.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]))
  };
  const body = options.body ?? null;
  if (body != null) {
    headers['content-length'] = String(Buffer.byteLength(body));
    if (!headers['content-type']) headers['content-type'] = 'application/x-www-form-urlencoded';
  }

  return new Promise((resolve, reject) => {
    const startedAt = process.hrtime.bigint();
    let settled = false;
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    const transport = isHttps ? https : http;
    const agent = isHttps
      ? rejectUnauthorized
        ? agents['https:']
        : agents['https-insecure']
      : agents['http:'];

    const req = transport.request(
      {
        protocol: parsed.protocol,
        hostname: parsed.hostname,
        port: parsed.port || (isHttps ? 443 : 80),
        path: `${parsed.pathname}${parsed.search}`,
        method,
        headers,
        agent,
        rejectUnauthorized,
        servername: isHttps && !/^[\d.]+$/.test(parsed.hostname) ? parsed.hostname : undefined
      },
      (res) => {
        const chunks = [];
        let received = 0;
        let truncated = false;
        let tls = null;

        res.on('data', (chunk) => {
          if (truncated) return;
          received += chunk.length;
          if (received > maxBytes) {
            const keep = Math.max(0, maxBytes - (received - chunk.length));
            if (keep > 0) chunks.push(chunk.subarray(0, keep));
            truncated = true;
            res.destroy();
            return;
          }
          chunks.push(chunk);
        });

        const complete = () => {
          finish(() => {
            const elapsedNs = process.hrtime.bigint() - startedAt;
            const raw = Buffer.concat(chunks);
            const decoded = truncated ? raw : decodeBody(raw, getHeader(res.headers, 'content-encoding'));
            try {
              tls = describeCertificate(res.socket, parsed.hostname);
            } catch {
              tls = null;
            }
            resolve({
              url: parsed.href,
              status: res.statusCode ?? 0,
              statusText: res.statusMessage ?? '',
              headers: { ...res.headers },
              setCookie: Array.isArray(res.headers['set-cookie']) ? res.headers['set-cookie'] : [],
              location: getHeader(res.headers, 'location'),
              body: decoded,
              bytes: decoded.length,
              receivedBytes: raw.length,
              truncated,
              elapsedMs: Number(elapsedNs / 1_000_000n),
              remoteAddress: res.socket?.remoteAddress ?? null,
              httpVersion: res.httpVersion,
              tls,
              request: { method, url: parsed.href, headers }
            });
          });
        };

        res.on('end', complete);
        res.on('close', complete);
        res.on('error', (error) => {
          finish(() => reject(new NetworkError(`Response error for ${url}: ${error.message}`, { url, cause: error.code })));
        });
      }
    );

    const timer = setTimeout(() => {
      finish(() => {
        req.destroy();
        reject(new NetworkError(`Request timed out after ${timeoutMs}ms: ${method} ${url}`, { url, code: 'ETIMEDOUT' }));
      });
    }, timeoutMs);

    req.on('error', (error) => {
      finish(() => reject(new NetworkError(`Request failed for ${url}: ${error.message}`, { url, code: error.code })));
    });

    options.signal?.addEventListener(
      'abort',
      () => {
        finish(() => {
          req.destroy();
          reject(new NetworkError(`Request aborted: ${method} ${url}`, { url, code: 'ABORTED' }));
        });
      },
      { once: true }
    );

    if (body != null) req.write(body);
    req.end();
  });
}

/** Thin client wrapper so the guard and tests share one place to close sockets. */
export class HttpClient {
  constructor({ userAgent = DEFAULT_UA } = {}) {
    this.userAgent = userAgent;
  }

  requestOnce(url, options = {}) {
    return requestOnce(url, { userAgent: this.userAgent, ...options });
  }

  close() {
    closeAgents();
  }
}

export { DEFAULT_UA, describeCertificate };
