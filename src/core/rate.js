import { LimitError } from './errors.js';
import { sleep } from './util.js';

/** Monotonic clock in milliseconds (immune to wall-clock jumps). */
function clock() {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

/**
 * Token bucket: `rate` tokens per second, bursting to `burst`.
 * `take()` resolves when a token is available, and is abortable.
 */
export class TokenBucket {
  constructor({ rate, burst = Math.max(1, Math.ceil(rate * 2)) }) {
    this.rate = Math.max(0.01, rate);
    this.burst = Math.max(1, burst);
    this.tokens = this.burst;
    this.updatedAt = clock();
    this.waiters = [];
    this.timer = null;
  }

  #refill() {
    const now = clock();
    const elapsed = (now - this.updatedAt) / 1000;
    if (elapsed > 0) {
      this.tokens = Math.min(this.burst, this.tokens + elapsed * this.rate);
      this.updatedAt = now;
    }
  }

  #drainWaiters() {
    this.#refill();
    while (this.waiters.length > 0 && this.tokens >= 1) {
      const waiter = this.waiters.shift();
      this.tokens -= 1;
      waiter.resolve();
    }
    if (this.waiters.length > 0 && !this.timer) {
      const need = (1 - this.tokens) / this.rate;
      this.timer = setTimeout(() => {
        this.timer = null;
        this.#drainWaiters();
      }, Math.max(5, Math.ceil(need * 1000)));
      this.timer.unref?.();
    }
  }

  /** @returns {Promise<void>} */
  async take(signal) {
    if (signal?.aborted) throw new LimitError('request cancelled before it started');
    this.#refill();
    if (this.tokens >= 1 && this.waiters.length === 0) {
      this.tokens -= 1;
      return;
    }
    await new Promise((resolve, reject) => {
      const waiter = { resolve: null, reject: null };
      waiter.resolve = () => {
        signal?.removeEventListener('abort', onAbort);
        resolve();
      };
      const onAbort = () => {
        const index = this.waiters.indexOf(waiter);
        if (index !== -1) this.waiters.splice(index, 1);
        reject(new LimitError('request cancelled while waiting for rate limit'));
      };
      waiter.reject = onAbort;
      signal?.addEventListener('abort', onAbort, { once: true });
      this.waiters.push(waiter);
      this.#drainWaiters();
    });
  }
}

/**
 * Counting semaphore with FIFO fairness and abort support.
 */
export class Semaphore {
  constructor(limit) {
    this.limit = Math.max(1, limit);
    this.active = 0;
    this.queue = [];
  }

  /** @returns {Promise<void>} */
  async acquire(signal) {
    if (signal?.aborted) throw new LimitError('cancelled before acquiring a slot');
    if (this.active < this.limit) {
      this.active += 1;
      return;
    }
    await new Promise((resolve, reject) => {
      const waiter = {
        grant: () => {
          signal?.removeEventListener('abort', onAbort);
          resolve();
        }
      };
      const onAbort = () => {
        const index = this.queue.indexOf(waiter);
        if (index !== -1) this.queue.splice(index, 1);
        reject(new LimitError('cancelled while waiting for a concurrency slot'));
      };
      signal?.addEventListener('abort', onAbort, { once: true });
      this.queue.push(waiter);
    });
  }

  release() {
    const next = this.queue.shift();
    if (next) {
      next.grant();
      return;
    }
    this.active = Math.max(0, this.active - 1);
  }

  /** Run `fn` while holding a slot. */
  async run(fn, signal) {
    await this.acquire(signal);
    try {
      return await fn();
    } finally {
      this.release();
    }
  }

  get pending() {
    return this.queue.length;
  }
}

/** Hard budget on the number of network operations in a run. */
export class Budget {
  constructor(maxRequests) {
    this.max = Math.max(1, maxRequests);
    this.used = 0;
    this.onExhausted = null;
  }

  /** Consume one unit or return false. */
  consume(n = 1) {
    if (this.used + n > this.max) {
      this.onExhausted?.();
      return false;
    }
    this.used += n;
    return true;
  }

  get remaining() {
    return Math.max(0, this.max - this.used);
  }
}

/**
 * Combined global + per-host rate limiting, concurrency, and request budget.
 * The guard owns one of these per run.
 */
export class RateLimiter {
  /**
   * @param {{requestsPerSecond: number, perHostRequestsPerSecond: number, concurrency: number, maxRequests: number}} limits
   */
  constructor(limits) {
    this.limits = limits;
    this.global = new TokenBucket({ rate: limits.requestsPerSecond });
    this.perHost = new Map();
    this.semaphore = new Semaphore(limits.concurrency);
    this.budget = new Budget(limits.maxRequests);
    this.deniedForBudget = 0;
  }

  #hostBucket(host) {
    let bucket = this.perHost.get(host);
    if (!bucket) {
      bucket = new TokenBucket({ rate: this.limits.perHostRequestsPerSecond });
      this.perHost.set(host, bucket);
    }
    return bucket;
  }

  /**
   * Wait for budget, global rate, per-host rate, and a concurrency slot.
   * The caller must call `release()` when done.
   */
  async acquire(host, signal) {
    if (!this.budget.consume(1)) {
      this.deniedForBudget += 1;
      throw new LimitError(`request budget exhausted (${this.limits.maxRequests} operations)`, { maxRequests: this.limits.maxRequests });
    }
    await this.global.take(signal);
    await this.#hostBucket(host || 'unknown').take(signal);
    await this.semaphore.acquire(signal);
  }

  release() {
    this.semaphore.release();
  }

  /** Let a paused caller chill for a while (used on 429/503). */
  async backoff(ms, signal) {
    await sleep(Math.min(Math.max(ms, 0), 30000), signal);
  }

  stats() {
    return {
      requests: this.budget.used,
      remaining: this.budget.remaining,
      budget: this.budget.max,
      active: this.semaphore.active,
      queued: this.semaphore.pending,
      perHost: Object.fromEntries([...this.perHost.entries()].map(([host, bucket]) => [host, Math.round(bucket.tokens * 10) / 10]))
    };
  }
}
