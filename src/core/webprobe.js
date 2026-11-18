import { NetworkError, ScopeError } from './errors.js';

/**
 * Work out which URL(s) to try for a target, HTTPS first for bare hostnames.
 * @param {{host?: string, url?: string, scheme?: string|null, port?: number|null}} target
 * @returns {string[]}
 */
export function candidateUrls(target) {
  const list = [];
  const add = (url) => {
    if (url && !list.includes(url)) list.push(url);
  };
  if (target.url) add(target.url);
  if (!target.host) return list;
  const host = target.host;
  const port = target.port ?? null;
  const scheme = target.scheme ?? null;
  if (scheme === 'https') {
    add(`https://${host}${port ? `:${port}` : ''}`);
    if (!port || port === 443) add(`http://${host}`);
  } else if (scheme === 'http') {
    add(`http://${host}${port ? `:${port}` : ''}`);
    if (!port || port === 80) add(`https://${host}`);
  } else {
    add(`https://${host}`);
    add(`http://${host}`);
  }
  return list;
}

/** Join a base URL and a path without duplicate slashes. */
export function joinUrl(base, pathname) {
  const baseUrl = String(base ?? '').replace(/\/+$/, '');
  const suffix = String(pathname ?? '').startsWith('/') ? String(pathname) : `/${pathname}`;
  return `${baseUrl}${suffix}`;
}

/**
 * Open the web root of a target, trying candidate schemes/ports until one answers.
 *
 * The result is cached on the guard so a dozen modules do not re-probe the same root.
 * @param {import('./guard.js').ScopeGuard} guard
 * @param {{host?: string, url?: string, scheme?: string|null, port?: number|null}} target
 * @param {{logger?: object, signal?: AbortSignal}} [options]
 * @returns {Promise<{url: string, scheme: string, port: number, status: number, headers: object,
 *   setCookie: string[], body: Buffer, text: string, session: object}|null>}
 */
export async function openWebTarget(guard, target, { logger = null, signal = null } = {}) {
  guard.webCache = guard.webCache ?? new Map();
  const cacheKey = target.url ?? `${target.host}|${target.scheme ?? ''}|${target.port ?? ''}`;
  if (guard.webCache.has(cacheKey)) return guard.webCache.get(cacheKey);

  for (const url of candidateUrls(target)) {
    try {
      const response = await guard.fetch(url, { signal, followRedirects: true });
      const parsed = new URL(response.url);
      const probe = {
        url: parsed.origin,
        scheme: parsed.protocol.slice(0, -1),
        port: parsed.port ? Number(parsed.port) : parsed.protocol === 'https:' ? 443 : 80,
        status: response.status,
        headers: response.response.headers,
        setCookie: response.response.setCookie,
        body: response.response.body,
        text: response.text,
        session: response
      };
      guard.webCache.set(cacheKey, probe);
      return probe;
    } catch (error) {
      if (error instanceof ScopeError) throw error;
      if (error instanceof NetworkError) {
        logger?.debug?.(`web probe failed for ${url}: ${error.message}`);
        continue;
      }
      throw error;
    }
  }
  guard.webCache.set(cacheKey, null);
  return null;
}
