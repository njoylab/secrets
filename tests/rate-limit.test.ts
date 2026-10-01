/**
 * Rate limiting against the real database.
 *
 * Counters live in PostgreSQL so limits hold across instances, and the check
 * and the increment share one statement: these tests verify the budget, the
 * per-subject isolation, the window rollover and that the GET side peek never
 * consumes quota.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { query } from '../src/lib/db.ts';
import type { RateLimitRule } from '../src/lib/env.ts';
import { CREATE_BUCKET, REVEAL_BUCKET, consumeRateLimit, peekRateLimit } from '../src/lib/rate-limit.ts';
import {
  countRateLimits,
  fetchRateLimitRows,
  insertRateLimitRow,
  resetEnv,
} from './helpers.ts';

const RULE: RateLimitRule = { max: 3, windowSeconds: 60 };
const OTHER_RULE: RateLimitRule = { max: 2, windowSeconds: 600 };

/** Age of a counter in seconds, measured by the database clock. */
async function windowAge(bucket: string, subject: string): Promise<number> {
  const { rows } = await query<{ age: number }>(
    `SELECT EXTRACT(EPOCH FROM (now() - window_started_at))::float8 AS age
       FROM rate_limits
      WHERE bucket = $1 AND subject = $2`,
    [bucket, subject],
  );
  const row = rows[0];
  if (!row) throw new Error('counter row missing');
  return row.age;
}

beforeEach(async () => {
  await resetEnv();
});

describe('consumeRateLimit: the budget', () => {
  it('allows the first max calls and refuses the next one', async () => {
    for (let call = 1; call <= RULE.max; call += 1) {
      const result = await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
      expect(result.allowed, `call ${call}`).toBe(true);
      expect(result.remaining).toBe(RULE.max - call);
      expect(result.retryAfterSeconds).toBe(RULE.windowSeconds);
    }

    const refused = await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    expect(refused.allowed).toBe(false);
    expect(refused.remaining).toBe(0);
    // Refused calls still count, so a flood cannot buy its way back in.
    const stillRefused = await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    expect(stillRefused.allowed).toBe(false);
  });

  it('grants an exact budget under concurrent calls', async () => {
    const calls = 20;
    const results = await Promise.all(
      Array.from({ length: calls }, () => consumeRateLimit(CREATE_BUCKET, 'subject-race', RULE)),
    );

    expect(results.filter((result) => result.allowed)).toHaveLength(RULE.max);
    expect(results.filter((result) => !result.allowed)).toHaveLength(calls - RULE.max);
    const rows = await fetchRateLimitRows(CREATE_BUCKET, 'subject-race');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.hits).toBe(calls);
  });
});

describe('consumeRateLimit: counter identity', () => {
  it('keeps one row per bucket and subject', async () => {
    await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);

    const rows = await fetchRateLimitRows(CREATE_BUCKET, 'subject-a');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.hits).toBe(3);
    expect(await countRateLimits()).toBe(1);
  });

  it('does not mix two subjects of the same bucket', async () => {
    await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    await consumeRateLimit(CREATE_BUCKET, 'subject-b', RULE);

    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-a'))[0]?.hits).toBe(2);
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-b'))[0]?.hits).toBe(1);
    // The last call of the budget belongs to subject-a, not to subject-b.
    expect((await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE)).allowed).toBe(true);
    expect((await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE)).allowed).toBe(false);
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-b'))[0]?.hits).toBe(1);
    expect((await consumeRateLimit(CREATE_BUCKET, 'subject-b', RULE)).allowed).toBe(true);
  });

  it('does not mix the same subject across buckets', async () => {
    await consumeRateLimit(CREATE_BUCKET, 'shared-ip', OTHER_RULE);
    await consumeRateLimit(REVEAL_BUCKET, 'shared-ip', RULE);

    expect((await fetchRateLimitRows(CREATE_BUCKET, 'shared-ip'))[0]?.hits).toBe(1);
    expect((await fetchRateLimitRows(REVEAL_BUCKET, 'shared-ip'))[0]?.hits).toBe(1);
    expect(await countRateLimits()).toBe(2);
  });

  it('applies each rule to its own bucket', async () => {
    const create = await consumeRateLimit(CREATE_BUCKET, 'subject-rules', OTHER_RULE);
    const reveal = await consumeRateLimit(REVEAL_BUCKET, 'subject-rules', RULE);
    expect(create.remaining).toBe(OTHER_RULE.max - 1);
    expect(reveal.remaining).toBe(RULE.max - 1);
  });
});

describe('consumeRateLimit: the window', () => {
  it('rolls over once the window has passed, resetting the counter', async () => {
    for (let call = 0; call < RULE.max; call += 1) {
      await consumeRateLimit(REVEAL_BUCKET, 'subject-window', RULE);
    }
    expect((await consumeRateLimit(REVEAL_BUCKET, 'subject-window', RULE)).allowed).toBe(false);
    expect(await windowAge(REVEAL_BUCKET, 'subject-window')).toBeLessThan(1);

    // Move the window start into the past: the next call starts a new window.
    await query(
      `UPDATE rate_limits SET window_started_at = now() - make_interval(secs => $3::double precision)
        WHERE bucket = $1 AND subject = $2`,
      [REVEAL_BUCKET, 'subject-window', RULE.windowSeconds + 5],
    );
    expect(await windowAge(REVEAL_BUCKET, 'subject-window')).toBeGreaterThan(RULE.windowSeconds);

    const afterRollover = await consumeRateLimit(REVEAL_BUCKET, 'subject-window', RULE);
    expect(afterRollover.allowed).toBe(true);
    expect(afterRollover.remaining).toBe(RULE.max - 1);

    const rows = await fetchRateLimitRows(REVEAL_BUCKET, 'subject-window');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.hits).toBe(1);
    expect(await windowAge(REVEAL_BUCKET, 'subject-window')).toBeLessThan(1);
  });

  it('keeps counting while the window is still open', async () => {
    await insertRateLimitRow(CREATE_BUCKET, 'stale-subject', 10, 1);
    expect(await windowAge(CREATE_BUCKET, 'stale-subject')).toBeGreaterThan(5);

    const result = await consumeRateLimit(CREATE_BUCKET, 'stale-subject', RULE);
    expect(result.allowed).toBe(true);
    // The counter continued from the stored value and the window did not move.
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'stale-subject'))[0]?.hits).toBe(2);
    expect(await windowAge(CREATE_BUCKET, 'stale-subject')).toBeGreaterThan(5);
  });
});

describe('peekRateLimit', () => {
  it('reports the full budget when the subject has never been seen', async () => {
    const peeked = await peekRateLimit(CREATE_BUCKET, 'never-seen', RULE);
    expect(peeked).toEqual({ allowed: true, remaining: RULE.max, retryAfterSeconds: RULE.windowSeconds });
    // A probe creates nothing: the form must still work.
    expect(await countRateLimits()).toBe(0);
  });

  it('reports the current usage without incrementing it', async () => {
    await consumeRateLimit(REVEAL_BUCKET, 'subject-peek', RULE);
    await consumeRateLimit(REVEAL_BUCKET, 'subject-peek', RULE);

    for (let probe = 0; probe < 5; probe += 1) {
      const peeked = await peekRateLimit(REVEAL_BUCKET, 'subject-peek', RULE);
      expect(peeked.allowed).toBe(true);
      expect(peeked.remaining).toBe(RULE.max - 2);
      expect(peeked.retryAfterSeconds).toBeGreaterThan(0);
      expect(peeked.retryAfterSeconds).toBeLessThanOrEqual(RULE.windowSeconds);
    }

    const rows = await fetchRateLimitRows(REVEAL_BUCKET, 'subject-peek');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.hits).toBe(2);
  });

  it('reports the exhausted budget once the limit is reached', async () => {
    for (let call = 0; call < RULE.max; call += 1) {
      await consumeRateLimit(CREATE_BUCKET, 'subject-dry', RULE);
    }
    const peeked = await peekRateLimit(CREATE_BUCKET, 'subject-dry', RULE);
    expect(peeked.allowed).toBe(false);
    expect(peeked.remaining).toBe(0);
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-dry'))[0]?.hits).toBe(RULE.max);
  });

  it('clamps the retry delay to zero for a counter whose window has passed', async () => {
    await insertRateLimitRow(CREATE_BUCKET, 'stale-peek', 3600, 1);
    const peeked = await peekRateLimit(CREATE_BUCKET, 'stale-peek', RULE);
    expect(peeked.retryAfterSeconds).toBe(0);
    expect(peeked.remaining).toBe(RULE.max - 1);
  });
});
