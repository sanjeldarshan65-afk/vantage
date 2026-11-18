/**
 * Deliberately misconfigured HTTP server for demos and end-to-end tests. Loopback only.
 * Weaknesses (all configuration-level, nothing exploitable):
 *   - no HSTS / CSP / X-Frame-Options / X-Content-Type-Options
 *   - version-disclosing Server and X-Powered-By headers
 *   - session cookie without Secure / HttpOnly / SameSite
 *   - CORS that reflects any Origin and allows credentials
 *   - plain HTTP only, a public /.git/HEAD and /.env (dummy values), no security.txt
 *   - "soft 404": unknown paths answer 200, to prove checks rely on content, not status
 */
import http from 'node:http';
import { fileURLToPath } from 'node:url';

/**
 * @param {number} [port] 0 picks a free port
 * @returns {Promise<{url: string, port: number, close: () => Promise<void>}>}
 */
export async function startLab(port = 0) {
  const server = http.createServer((req, res) => {
    const headers = {
      'content-type': 'text/html; charset=utf-8',
      server: 'Apache/2.4.29 (Ubuntu)',
      'x-powered-by': 'PHP/7.2.24',
      'set-cookie': 'PHPSESSID=lab0000000000000000demo; path=/'
    };
    if (req.headers.origin) {
      headers['access-control-allow-origin'] = req.headers.origin;
      headers['access-control-allow-credentials'] = 'true';
    }
    // Fake leaked files (values are dummies) so the exposure checks have something to find.
    const leaks = {
      '/.git/HEAD': 'ref: refs/heads/main\n',
      '/.env': 'APP_NAME=lab\nDB_HOST=127.0.0.1\nDB_PASSWORD=not-a-real-password\nSTRIPE_SECRET_KEY=sk_test_dummy\n'
    };
    if (leaks[req.url]) {
      res.writeHead(200, { ...headers, 'content-type': 'text/plain' });
      res.end(req.method === 'HEAD' ? undefined : leaks[req.url]);
      return;
    }
    // Soft 404: every unknown path answers 200 with the home page, like many real sites.
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' ? undefined : '<!doctype html><title>Lab</title><h1>VANTAGE lab target</h1>');
  });
  await new Promise((resolve) => server.listen(port, '127.0.0.1', resolve));
  const actual = server.address().port;
  return {
    url: `http://127.0.0.1:${actual}`,
    port: actual,
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); })
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const lab = await startLab(Number(process.argv[2] ?? 8088));
  console.log(`lab target listening on ${lab.url} (Ctrl+C to stop)`);
}
