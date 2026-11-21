import { RateLimitError } from '@acme/auth-core';
import type { EphemeralStore } from '../adapters/types.js';
import type { Clock } from '../util/clock.js';

export interface BackoffPolicy {
  /** Failures allowed inside the window before delays start. */
  freeAttempts: number;
  /** Failures older than this are forgotten. */
  windowSec: number;
  /** The first delay. Every further failure doubles it. */
  baseDelaySec: number;
  maxDelaySec: number;
}

/**
 * Counts failures in the ephemeral store and turns them into waiting periods.
 *
 * Two shapes are offered. Backoff, for password attempts: a growing delay with an upper bound, so
 * an attacker is slowed down but cannot lock a victim out for good. Fixed window, for second
 * factors: a hard cap on failures per window.
 */
export class Throttle {
  constructor(
    private readonly store: EphemeralStore,
    private readonly clock: Clock,
  ) {}

  /** Throws `RATE_LIMITED` with `details.retryAfterSec` while `key` is in a delay. */
  async assertNotBlocked(key: string): Promise<void> {
    const until = await this.store.get(`rl:block:${key}`);
    const now = this.clock.nowSec();
    if (typeof until === 'number' && until > now) {
      throw new RateLimitError('RATE_LIMITED', { details: { retryAfterSec: until - now } });
    }
  }

  /** Records a failure and starts a delay once the free attempts are used up. Returns the failure count. */
  async recordFailure(key: string, policy: BackoffPolicy): Promise<number> {
    const count = await this.store.increment(`rl:count:${key}`, policy.windowSec);
    if (count >= policy.freeAttempts) {
      const doublings = Math.min(count - policy.freeAttempts, 30);
      const delay = Math.min(policy.maxDelaySec, policy.baseDelaySec * 2 ** doublings);
      await this.store.set(`rl:block:${key}`, this.clock.nowSec() + delay, delay);
    }
    return count;
  }

  /** Failures recorded for `key` inside the current window. */
  async failureCount(key: string): Promise<number> {
    const count = await this.store.get(`rl:count:${key}`);
    return typeof count === 'number' ? count : 0;
  }

  /** Forgets the failures and any delay for `key`. */
  async reset(key: string): Promise<void> {
    await this.store.take(`rl:count:${key}`);
    await this.store.take(`rl:block:${key}`);
  }

  /** Throws `RATE_LIMITED` once `key` has `max` failures in its current fixed window. */
  async assertBelowLimit(key: string, max: number): Promise<void> {
    const count = await this.store.get(`rl:window:${key}`);
    if (typeof count === 'number' && count >= max) {
      const until = await this.store.get(`rl:window-end:${key}`);
      const now = this.clock.nowSec();
      const retryAfterSec = typeof until === 'number' && until > now ? until - now : 1;
      throw new RateLimitError('RATE_LIMITED', { details: { retryAfterSec } });
    }
  }

  /** Records a failure in a fixed window that starts at the first failure. */
  async recordWindowFailure(key: string, windowSec: number): Promise<number> {
    const count = await this.store.increment(`rl:window:${key}`, windowSec);
    if (count === 1) await this.store.set(`rl:window-end:${key}`, this.clock.nowSec() + windowSec, windowSec);
    return count;
  }
}
