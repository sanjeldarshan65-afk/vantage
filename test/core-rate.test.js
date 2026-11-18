import test from 'node:test';
import assert from 'node:assert/strict';
import { TokenBucket, Semaphore, Budget, RateLimiter } from '../src/core/rate.js';
import { LimitError } from '../src/core/errors.js';

const limits = { requestsPerSecond: 100, perHostRequestsPerSecond: 100, concurrency: 2, maxRequests: 5 };

test('token bucket bursts then paces', async () => {
  const bucket = new TokenBucket({ rate: 40, burst: 1 });
  const started = Date.now();
  await bucket.take();
  await bucket.take();
  await bucket.take();
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 40, `three takes at 40/s should take >= 40ms, took ${elapsed}ms`);
});

test('token bucket take is abortable', async () => {
  const bucket = new TokenBucket({ rate: 1, burst: 1 });
  await bucket.take();
  const controller = new AbortController();
  const pending = bucket.take(controller.signal);
  controller.abort();
  await assert.rejects(pending, LimitError);
});

test('budget stops at the limit', () => {
  const budget = new Budget(3);
  assert.equal(budget.consume(), true);
  assert.equal(budget.consume(), true);
  assert.equal(budget.consume(), true);
  assert.equal(budget.consume(), false);
  assert.equal(budget.remaining, 0);
  assert.equal(budget.used, 3);
});

test('semaphore enforces its limit and releases', async () => {
  const semaphore = new Semaphore(2);
  let active = 0;
  let maxActive = 0;
  const work = async () => {
    await semaphore.acquire();
    active += 1;
    maxActive = Math.max(maxActive, active);
    await new Promise((resolve) => setTimeout(resolve, 10));
    active -= 1;
    semaphore.release();
  };
  await Promise.all([work(), work(), work(), work()]);
  assert.equal(maxActive, 2);
  assert.equal(semaphore.active, 0);
  assert.equal(semaphore.pending, 0);
});

test('semaphore acquire honours abort while queued', async () => {
  const semaphore = new Semaphore(1);
  await semaphore.acquire();
  const controller = new AbortController();
  const queued = semaphore.acquire(controller.signal);
  controller.abort();
  await assert.rejects(queued, LimitError);
  semaphore.release();
  assert.equal(semaphore.pending, 0);
});

test('rate limiter enforces the request budget', async () => {
  const limiter = new RateLimiter({ ...limits, maxRequests: 2 });
  await limiter.acquire('a.example');
  limiter.release();
  await limiter.acquire('a.example');
  limiter.release();
  await assert.rejects(() => limiter.acquire('a.example'), LimitError);
  assert.equal(limiter.budget.used, 2);
  assert.equal(limiter.stats().remaining, 0);
});

test('rate limiter tracks per-host buckets and concurrency', async () => {
  const limiter = new RateLimiter(limits);
  await limiter.acquire('one.example');
  await limiter.acquire('two.example');
  let thirdStarted = false;
  const third = limiter.acquire('three.example').then(() => {
    thirdStarted = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(thirdStarted, false, 'concurrency limit should hold the third slot');
  limiter.release();
  await third;
  limiter.release();
  limiter.release();
  const stats = limiter.stats();
  assert.equal(stats.requests, 3);
  assert.equal(stats.budget, 5);
  assert.ok('one.example' in stats.perHost);
});

test('backoff resolves quickly and is abortable', async () => {
  const limiter = new RateLimiter(limits);
  const controller = new AbortController();
  const started = Date.now();
  const pending = limiter.backoff(5000, controller.signal);
  controller.abort();
  await pending;
  assert.ok(Date.now() - started < 1000, 'abort should cut the backoff short');
});
