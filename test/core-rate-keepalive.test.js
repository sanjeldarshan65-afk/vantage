import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Regression: a caller waiting on the rate limiter is the only pending work in a CLI run against a
// remote target. If the refill timer is unref'd, Node exits with code 0 mid-run and the run is lost.
test('a caller waiting for a rate-limit token keeps the process alive', () => {
  const rate = fileURLToPath(new URL('../src/core/rate.js', import.meta.url));
  const script = `
    const { RateLimiter } = await import(${JSON.stringify(new URL(`file:///${rate.replace(/\\/g, '/')}`).href)});
    const limiter = new RateLimiter({ requestsPerSecond: 50, perHostRequestsPerSecond: 2, concurrency: 4, maxRequests: 100 });
    for (let i = 0; i < 5; i++) { await limiter.acquire('host'); limiter.release(); }
    console.log('reached the end');
  `;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8', timeout: 15000 });
  assert.match(out, /reached the end/);
});
