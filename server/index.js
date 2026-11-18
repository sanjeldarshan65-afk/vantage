import http from 'node:http';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { silentLogger } from '../src/core/log.js';
import { engagementsDir } from '../src/core/paths.js';
import { createApiHandler, sendJson } from './api.js';
import { EventBus } from './sse.js';

const here = path.dirname(fileURLToPath(import.meta.url));

/** Absolute path of the static dashboard directory. */
export const UI_DIR = path.resolve(here, '..', 'ui');

/** Static asset content types. Anything else is refused rather than guessed. */
const CONTENT_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8'
});

/** Headers applied to every response. */
const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer'
});

/**
 * Normalize the configured data directory.
 *
 * Callers may pass either the directory that holds engagement folders (an `engagements` root) or
 * the data directory that contains it. The two are told apart by name, then by layout.
 * @param {string} [configured]
 * @returns {string} absolute path of the engagements root
 */
export function resolveEngagementsRoot(configured) {
  const resolved = path.resolve(configured ?? engagementsDir());
  if (path.basename(resolved).toLowerCase() === 'engagements') return resolved;
  return path.join(resolved, 'engagements');
}

/**
 * Resolve a URL pathname to a file under `ui/`, refusing anything that escapes the directory.
 * @param {string} pathname percent-encoded URL pathname
 * @returns {{file: string} | {status: number, code: string, error: string}}
 */
export function resolveStaticFile(pathname) {
  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return { status: 400, code: 'path.invalid', error: 'Malformed URL path.' };
  }
  if (decoded.includes('\0')) return { status: 400, code: 'path.invalid', error: 'Malformed URL path.' };
  const relative = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  const file = path.resolve(UI_DIR, relative);
  const prefix = UI_DIR.endsWith(path.sep) ? UI_DIR : `${UI_DIR}${path.sep}`;
  if (file !== UI_DIR && !file.startsWith(prefix)) {
    return { status: 400, code: 'path.invalid', error: 'Invalid static path.' };
  }
  return { file };
}

/**
 * VANTAGE local dashboard server.
 *
 * Binds loopback only (the host is not configurable), serves the static UI from `ui/` and routes
 * `/api/*` to the JSON API. The returned object exposes the generated token and the {@link EventBus}
 * the CLI feeds with engine progress.
 *
 * @param {{dataDir?: string, engagementsRoot?: string, token?: string, logger?: object, bus?: EventBus}} [options]
 * @returns {{server: import('node:http').Server, token: string, bus: EventBus, engagementsRoot: string,
 *   url: string|null, start: (port?: number) => Promise<string>, close: () => Promise<void>}}
 */
export function createServer({ dataDir, engagementsRoot, token, logger, bus } = {}) {
  const log = logger ?? silentLogger();
  const root = engagementsRoot ? path.resolve(engagementsRoot) : resolveEngagementsRoot(dataDir);
  const serverToken = token ?? randomBytes(24).toString('hex');
  const eventBus = bus instanceof EventBus ? bus : new EventBus();

  const handleApi = createApiHandler({ engagementsRoot: root, token: serverToken, logger: log, bus: eventBus });

  async function serveStatic(req, res, url) {
    const method = req.method ?? 'GET';
    if (method !== 'GET' && method !== 'HEAD') {
      res.setHeader('Allow', 'GET, HEAD');
      sendJson(res, 405, { error: 'Method not allowed.', code: 'method.not_allowed' });
      return;
    }
    const target = resolveStaticFile(url.pathname);
    if (!target.file) {
      sendJson(res, target.status, { error: target.error, code: target.code });
      return;
    }
    const extension = path.extname(target.file).toLowerCase();
    const contentType = CONTENT_TYPES[extension];
    if (!contentType) {
      sendJson(res, 404, { error: 'Not found.', code: 'not_found' });
      return;
    }
    let body;
    try {
      body = await fs.readFile(target.file);
    } catch (error) {
      if (error?.code === 'ENOENT' || error?.code === 'EISDIR') {
        sendJson(res, 404, { error: 'Not found.', code: 'not_found' });
        return;
      }
      throw error;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': body.length,
      'Cache-Control': 'no-cache'
    });
    res.end(method === 'HEAD' ? undefined : body);
  }

  const server = http.createServer(async (req, res) => {
    const started = process.hrtime.bigint();
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    res.on('finish', () => {
      const elapsedMs = Number((process.hrtime.bigint() - started) / 1_000_000n);
      log.debug?.(`${req.method} ${res.statusCode} ${req.url} ${elapsedMs}ms`);
    });

    let url;
    try {
      url = new URL(req.url ?? '/', 'http://127.0.0.1');
    } catch {
      sendJson(res, 400, { error: 'Malformed request URL.', code: 'request.invalid' });
      return;
    }

    try {
      if (url.pathname === '/api' || url.pathname.startsWith('/api/')) {
        await handleApi(req, res, url);
      } else {
        await serveStatic(req, res, url);
      }
    } catch (error) {
      log.error?.(`unhandled request error: ${error?.stack ?? error?.message ?? error}`);
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'Internal server error.', code: 'internal.error' });
      } else if (!res.writableEnded) {
        res.end();
      }
    }
  });

  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  server.on('error', (error) => log.error?.(`server error: ${error.message}`));

  const instance = {
    server,
    token: serverToken,
    bus: eventBus,
    engagementsRoot: root,
    /** Loopback URL of the running server, or null before `start()`/after `close()`. */
    get url() {
      const address = server.address();
      if (!address || typeof address === 'string') return null;
      return `http://127.0.0.1:${address.port}`;
    },
    /**
     * Start listening on the loopback interface only.
     * @param {number} [port] 0 picks a free port
     * @returns {Promise<string>} the URL clients should use
     */
    async start(port = 0) {
      if (server.listening) return instance.url;
      if (!Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError(`Invalid port: ${port}`);
      await new Promise((resolve, reject) => {
        const onError = (error) => {
          server.off('listening', onListening);
          reject(error);
        };
        const onListening = () => {
          server.off('error', onError);
          resolve();
        };
        server.once('error', onError);
        server.once('listening', onListening);
        server.listen(port, '127.0.0.1');
      });
      log.debug?.(`vantage dashboard listening on ${instance.url}`);
      return instance.url;
    },
    /** Stop listening and drop open connections (SSE streams would otherwise hold the server). */
    async close() {
      if (!server.listening) return;
      await new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections?.();
        server.closeIdleConnections?.();
      });
    }
  };

  return instance;
}

export { EventBus } from './sse.js';
