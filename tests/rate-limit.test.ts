/**
 * Rate limiting against the real database.
 *
 * Counters live in PostgreSQL so limits hold across instances, and the check
 * and the increment share one statement: these tests verify the budget, the
 * per-subject isolation and the window rollover. The subject mapping is pure and
 * checked without the database.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { query } from '../src/lib/db.ts';
import type { RateLimitRule } from '../src/lib/env.ts';
import { CREATE_BUCKET, REVEAL_BUCKET, consumeRateLimit, rateLimitSubject } from '../src/lib/rate-limit.ts';
import {
  countRateLimits,
  fetchRateLimitRows,
  insertRateLimitRow,
  resetEnv,
} from './helpers.ts';
import { normalizeAddress } from '../src/lib/address.mjs';

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
    // The counter is already at the cap, so further refusals change nothing and
    // the flood cannot buy its way back in.
    const stillRefused = await consumeRateLimit(CREATE_BUCKET, 'subject-a', RULE);
    expect(stillRefused.allowed).toBe(false);
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-a'))[0]?.hits).toBe(RULE.max + 1);
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
    // The counter stops one past the cap: a flood cannot inflate the row, and
    // stopping at max instead would leave the subject allowed for the rest of
    // the window.
    expect(rows[0]?.hits).toBe(RULE.max + 1);
  });

  it('keeps refusing after the cap, without reopening the window', async () => {
    for (let call = 0; call < RULE.max + 5; call += 1) {
      await consumeRateLimit(CREATE_BUCKET, 'subject-capped', RULE);
    }
    const ageBefore = await windowAge(CREATE_BUCKET, 'subject-capped');
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-capped'))[0]?.hits).toBe(RULE.max + 1);

    const refused = await consumeRateLimit(CREATE_BUCKET, 'subject-capped', RULE);
    expect(refused.allowed).toBe(false);
    expect(refused.remaining).toBe(0);
    expect((await fetchRateLimitRows(CREATE_BUCKET, 'subject-capped'))[0]?.hits).toBe(RULE.max + 1);
    // The refusal did not move the window, so the budget is still exhausted.
    expect(await windowAge(CREATE_BUCKET, 'subject-capped')).toBeLessThan(ageBefore + 1);
  });

  it('reports only what is left of the window on a refusal', async () => {
    // A window already three quarters spent: the caller must be told to come
    // back in seconds, not to wait out the whole window again.
    await insertRateLimitRow(CREATE_BUCKET, 'subject-partial', RULE.windowSeconds * 0.75, RULE.max);

    const refused = await consumeRateLimit(CREATE_BUCKET, 'subject-partial', RULE);
    expect(refused.allowed).toBe(false);
    expect(refused.retryAfterSeconds).toBeGreaterThan(0);
    expect(refused.retryAfterSeconds).toBeLessThan(RULE.windowSeconds);
    expect(refused.retryAfterSeconds).toBeLessThanOrEqual(Math.ceil(RULE.windowSeconds * 0.25) + 1);
  });

  it('never reports a retry delay below one second on a refusal', async () => {
    // The window is still open but has under a second left, so the remaining
    // time truncates to zero. A zero delay would invite an immediate hot loop.
    await insertRateLimitRow(CREATE_BUCKET, 'subject-expiring', RULE.windowSeconds - 0.5, RULE.max);

    const refused = await consumeRateLimit(CREATE_BUCKET, 'subject-expiring', RULE);
    expect(refused.allowed).toBe(false);
    expect(refused.retryAfterSeconds).toBe(1);
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

describe('rateLimitSubject', () => {
  it('keeps IPv4 addresses, including ones unwrapped from the mapped form', () => {
    expect(rateLimitSubject('203.0.113.7')).toBe('203.0.113.7');
    expect(rateLimitSubject(normalizeAddress('::ffff:203.0.113.7'))).toBe('203.0.113.7');
  });

  it('charges every address of an IPv6 /64 to one subject', () => {
    const subject = '2001:db8:85a3:12::/64';
    expect(rateLimitSubject('2001:0db8:85a3:0012:0000:8a2e:0370:7334')).toBe(subject);
    expect(rateLimitSubject('2001:db8:85a3:12::1')).toBe(subject);
    expect(rateLimitSubject('2001:db8:85a3:12:ffff:ffff:ffff:ffff')).toBe(subject);
    expect(rateLimitSubject('2001:DB8:85A3:12::abcd')).toBe(subject);
    // A neighbouring /64 is a different subscriber.
    expect(rateLimitSubject('2001:db8:85a3:13::1')).toBe('2001:db8:85a3:13::/64');
  });

  it('expands :: wherever it sits', () => {
    expect(rateLimitSubject('::1')).toBe('0:0:0:0::/64');
    expect(rateLimitSubject('::')).toBe('0:0:0:0::/64');
    expect(rateLimitSubject('2001:db8::')).toBe('2001:db8:0:0::/64');
    expect(rateLimitSubject('2001:db8::5:6:7:8')).toBe('2001:db8:0:0::/64');
    expect(rateLimitSubject('fe80::1:2:3:4:5')).toBe('fe80:0:0:1::/64');
    expect(rateLimitSubject('64:ff9b::192.0.2.1')).toBe('64:ff9b:0:0::/64');
  });

  it('never folds an IPv6 subject onto an IPv4 one', () => {
    expect(rateLimitSubject('::ffff:203.0.113.7')).toBe('0:0:0:0::/64');
    expect(rateLimitSubject('::ffff:203.0.113.7')).not.toBe('203.0.113.7');
  });

  it('leaves unknown and unparsable values unchanged', () => {
    for (const value of [
      'unknown',
      '',
      'not-an-address',
      '1:2:3:4:5:6:7:8:9',
      '1:2:3:4:5:6:7',
      '1::2::3',
      '1:2:3:4:5:6:7::8',
      '12345::1',
      'g::1',
      '1.2.3.4::1',
      '::1.2.3.256',
      'fe80::1%eth0',
    ]) {
      expect(rateLimitSubject(value)).toBe(value);
    }
  });
});
