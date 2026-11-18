import net from 'node:net';
import tls from 'node:tls';
import { describeCertificate } from './http.js';

/**
 * A single TCP connect probe. Opens the socket, optionally reads the first bytes a service
 * volunteers (banner), then closes. Never writes to the target.
 *
 * @param {string} host
 * @param {number} port
 * @param {{timeoutMs?: number, bannerBytes?: number}} [options]
 * @returns {Promise<{open: boolean, elapsedMs: number, banner: Buffer|null, error: string|null}>}
 */
export function tcpProbe(host, port, { timeoutMs = 3000, bannerBytes = 256 } = {}) {
  return new Promise((resolve) => {
    const startedAt = process.hrtime.bigint();
    const elapsed = () => Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
    const chunks = [];
    let received = 0;
    let settled = false;

    const socket = new net.Socket();
    let timer = null;
    let bannerTimer = null;

    const done = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(bannerTimer);
      socket.destroy();
      resolve({ elapsedMs: elapsed(), ...result });
    };

    socket.setTimeout(timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      // Give a service a short window to greet us, then stop reading.
      bannerTimer = setTimeout(() => {
        done({ open: true, banner: chunks.length ? Buffer.concat(chunks) : null, error: null });
      }, Math.min(400, timeoutMs));
      socket.on('data', (chunk) => {
        if (received >= bannerBytes) return;
        const room = bannerBytes - received;
        const slice = chunk.length > room ? chunk.subarray(0, room) : chunk;
        chunks.push(slice);
        received += slice.length;
        if (received >= bannerBytes) done({ open: true, banner: Buffer.concat(chunks), error: null });
      });
      socket.on('error', () => done({ open: true, banner: chunks.length ? Buffer.concat(chunks) : null, error: null }));
    });
    socket.once('timeout', () => done({ open: false, banner: null, error: 'ETIMEDOUT' }));
    socket.once('error', (error) => done({ open: false, banner: null, error: error.code ?? error.message }));

    timer = setTimeout(() => done({ open: false, banner: null, error: 'ETIMEDOUT' }), timeoutMs);
    try {
      socket.connect({ host, port });
    } catch (error) {
      done({ open: false, banner: null, error: error.code ?? error.message });
    }
  });
}

/**
 * A single TLS handshake probe. Verification is off on purpose: the point is to observe the
 * certificate and negotiated protocol, not to trust the endpoint.
 *
 * @param {string} host
 * @param {number} port
 * @param {{timeoutMs?: number, servername?: string, minVersion?: string, maxVersion?: string}} [options]
 * @returns {Promise<{open: boolean, elapsedMs: number, tls: object|null, error: string|null}>}
 */
export function tlsProbe(host, port, { timeoutMs = 5000, servername, minVersion, maxVersion } = {}) {
  return new Promise((resolve) => {
    const startedAt = process.hrtime.bigint();
    const elapsed = () => Number((process.hrtime.bigint() - startedAt) / 1_000_000n);
    let settled = false;
    const serverName = servername ?? host;

    let socket;
    try {
      socket = tls.connect({
        host,
        port,
        servername: serverName,
        rejectUnauthorized: false,
        minVersion,
        maxVersion,
        timeout: timeoutMs
      });
    } catch (error) {
      resolve({ open: false, elapsedMs: 0, tls: null, error: error.code ?? error.message });
      return;
    }

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve({ elapsedMs: elapsed(), ...result });
    };

    socket.once('secureConnect', () => {
      finish({ open: true, error: null, tls: describeCertificate(socket, serverName) });
    });
    socket.once('timeout', () => finish({ open: false, tls: null, error: 'ETIMEDOUT' }));
    socket.once('error', (error) => finish({ open: false, tls: null, error: error.code ?? error.message }));
    const timer = setTimeout(() => finish({ open: false, tls: null, error: 'ETIMEDOUT' }), timeoutMs);
  });
}
