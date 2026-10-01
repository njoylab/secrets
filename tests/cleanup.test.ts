/**
 * Periodic maintenance: `purgeExpired` is the in-process twin of
 * `scripts/cleanup.mjs`, and the same invariants must hold for both.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { hashToken } from '../src/lib/crypto.ts';
import { query } from '../src/lib/db.ts';
import { createSecret, purgeExpired, revealSecret } from '../src/lib/secrets.ts';
import {
  DEFAULT_CLEANUP_KEEP_COUNTER_SECONDS,
  DEFAULT_RATE_LIMIT_CREATE_WINDOW_SECONDS,
  DEFAULT_RATE_LIMIT_REVEAL_WINDOW_SECONDS,
  counterRetention,
  parseSeconds,
} from '../src/lib/retention.mjs';
import {
  countRateLimits,
  countSecrets,
  fetchRateLimitRows,
  fetchSecretRow,
  forceExpire,
  insertRateLimitRow,
  resetEnv,
  secretRowJson,
  setExpiresInSeconds,
} from './helpers.ts';

const HOUR = 3600;

beforeEach(async () => {
  await resetEnv();
});

describe('purgeExpired: secrets', () => {
  it('removes every expired secret and keeps every live one', async () => {
    const expiredShort = await createSecret({ secret: 'expired short', expiresInDays: 1 });
    const expiredLong = await createSecret({ secret: 'expired long', expiresInDays: 30 });
    const live = await createSecret({ secret: 'live', expiresInDays: 30 });
    const liveLocked = await createSecret({ secret: 'live locked', expiresInDays: 7, password: 'pw-probe' });
    await forceExpire(expiredShort.token);
    await setExpiresInSeconds(expiredLong.token, -1);

    const result = await purgeExpired(HOUR);
    expect(result).toEqual({ secrets: 2, counters: 0 });
    expect(await countSecrets()).toBe(2);

    expect(await fetchSecretRow(expiredShort.token)).toBeUndefined();
    expect(await fetchSecretRow(expiredLong.token)).toBeUndefined();
    expect(await fetchSecretRow(live.token)).toBeDefined();
    expect(await fetchSecretRow(liveLocked.token)).toBeDefined();
  });

  it('leaves a live row byte for byte identical', async () => {
    const live = await createSecret({ secret: 'untouched', expiresInDays: 7, password: 'pw-probe' });
    const before = await secretRowJson(live.token);

    expect(await purgeExpired(HOUR)).toEqual({ secrets: 0, counters: 0 });
    expect(await secretRowJson(live.token)).toBe(before);
    expect(await revealSecret(live.token, 'pw-probe')).toEqual({ ok: true, secret: 'untouched' });
  });

  it('treats an expiry exactly at now as expired, in SQL', async () => {
    const boundary = await createSecret({ secret: 'boundary', expiresInDays: 1 });
    await query(`UPDATE secrets SET expires_at = now() - interval '1 millisecond' WHERE token_hash = $1`, [
      hashToken(boundary.token),
    ]);

    expect(await purgeExpired(HOUR)).toEqual({ secrets: 1, counters: 0 });
    expect(await fetchSecretRow(boundary.token)).toBeUndefined();
  });

  it('is idempotent: a second run finds nothing left to remove', async () => {
    const expired = await createSecret({ secret: 'gone', expiresInDays: 1 });
    await forceExpire(expired.token);

    expect(await purgeExpired(HOUR)).toEqual({ secrets: 1, counters: 0 });
    expect(await purgeExpired(HOUR)).toEqual({ secrets: 0, counters: 0 });
    expect(await countSecrets()).toBe(0);
  });
});

describe('counterRetention', () => {
  it('keeps the defaults, so the current behaviour does not change', () => {
    expect(DEFAULT_CLEANUP_KEEP_COUNTER_SECONDS).toBe(3600);
    expect(DEFAULT_RATE_LIMIT_CREATE_WINDOW_SECONDS).toBe(3600);
    expect(DEFAULT_RATE_LIMIT_REVEAL_WINDOW_SECONDS).toBe(300);
    expect(counterRetention({})).toEqual({ configuredSeconds: 3600, effectiveSeconds: 3600 });
  });

  it('raises a retention shorter than a rate limit window', () => {
    // Removing a counter whose window is still open resets that subject's
    // budget, so the retention can only grow.
    expect(
      counterRetention({ CLEANUP_KEEP_COUNTER_SECONDS: '100', RATE_LIMIT_CREATE_WINDOW_SECONDS: '3600' }),
    ).toEqual({ configuredSeconds: 100, effectiveSeconds: 3600 });
    expect(
      counterRetention({
        CLEANUP_KEEP_COUNTER_SECONDS: '100',
        RATE_LIMIT_CREATE_WINDOW_SECONDS: '7200',
        RATE_LIMIT_REVEAL_WINDOW_SECONDS: '300',
      }),
    ).toEqual({ configuredSeconds: 100, effectiveSeconds: 7200 });
    expect(
      counterRetention({
        CLEANUP_KEEP_COUNTER_SECONDS: '0',
        RATE_LIMIT_CREATE_WINDOW_SECONDS: '10',
        RATE_LIMIT_REVEAL_WINDOW_SECONDS: '900',
      }),
    ).toEqual({ configuredSeconds: 0, effectiveSeconds: 900 });
  });

  it('leaves a retention longer than every window alone', () => {
    expect(
      counterRetention({
        CLEANUP_KEEP_COUNTER_SECONDS: '86400',
        RATE_LIMIT_CREATE_WINDOW_SECONDS: '3600',
        RATE_LIMIT_REVEAL_WINDOW_SECONDS: '300',
      }),
    ).toEqual({ configuredSeconds: 86400, effectiveSeconds: 86400 });
  });

  it('falls back to the defaults on a blank or unusable value', () => {
    for (const value of ['', '   ', 'not-a-number', '-1']) {
      expect(counterRetention({ CLEANUP_KEEP_COUNTER_SECONDS: value }), value).toEqual({
        configuredSeconds: 3600,
        effectiveSeconds: 3600,
      });
    }
  });

  it('rejects a trailing suffix instead of reading the leading digits', () => {
    // `100foo` must not pass the script's validation as 100 and then be re-read
    // as unusable, which would silently run the cleanup with the 3600s default.
    expect(parseSeconds('100foo')).toBeUndefined();
    expect(counterRetention({ CLEANUP_KEEP_COUNTER_SECONDS: '100foo' })).toEqual({
      configuredSeconds: 3600,
      effectiveSeconds: 3600,
    });
  });
});

describe('parseSeconds', () => {
  it('accepts a plain non-negative integer, with optional surrounding space', () => {
    const cases: ReadonlyArray<readonly [string, number]> = [
      ['0', 0],
      ['100', 100],
      ['  100  ', 100],
      ['86400', 86400],
    ];
    for (const [value, expected] of cases) {
      expect(parseSeconds(value), value).toBe(expected);
    }
  });

  it('rejects anything that is not exactly a non-negative integer', () => {
    for (const value of [
      undefined,
      '',
      '   ',
      'abc',
      '100foo',
      'foo100',
      '1.5',
      '-1',
      '1e3',
      '+1',
      '0x10',
      '99999999999999999999',
    ]) {
      expect(parseSeconds(value), String(value)).toBeUndefined();
    }
  });
});

describe('purgeExpired: counters', () => {
  it('removes idle counters and keeps fresh ones', async () => {
    await insertRateLimitRow('create', 'idle-subject', 2 * HOUR, 3);
    await insertRateLimitRow('create', 'fresh-subject', 5, 3);
    await insertRateLimitRow('reveal', 'idle-other', 3 * HOUR, 1);
    await insertRateLimitRow('reveal', 'fresh-other', 60, 1);

    const result = await purgeExpired(HOUR);
    expect(result).toEqual({ secrets: 0, counters: 2 });

    expect(await fetchRateLimitRows('create', 'idle-subject')).toHaveLength(0);
    expect(await fetchRateLimitRows('reveal', 'idle-other')).toHaveLength(0);
    expect(await fetchRateLimitRows('create', 'fresh-subject')).toHaveLength(1);
    expect(await fetchRateLimitRows('reveal', 'fresh-other')).toHaveLength(1);
    expect(await countRateLimits()).toBe(2);
  });

  it('honours a different retention for counters than for secrets', async () => {
    await insertRateLimitRow('create', 'mid-subject', 120, 1);
    await insertRateLimitRow('create', 'old-subject', 600, 1);

    expect(await purgeExpired(300)).toEqual({ secrets: 0, counters: 1 });
    expect(await fetchRateLimitRows('create', 'mid-subject')).toHaveLength(1);
    expect(await fetchRateLimitRows('create', 'old-subject')).toHaveLength(0);
  });

  it('uses the window start, not the last hit, to decide idleness', async () => {
    // A counter that was just used still started its window long ago: it is the
    // window that is retained, so the row goes as soon as the window is older
    // than the retention, and the budget resets on the next request.
    await insertRateLimitRow('create', 'busy-subject', 2 * HOUR, 9);
    expect(await purgeExpired(HOUR)).toEqual({ secrets: 0, counters: 1 });
    expect(await fetchRateLimitRows('create', 'busy-subject')).toHaveLength(0);
  });

  it('keeps a counter whose window is still inside the retention', async () => {
    await insertRateLimitRow('create', 'edge-subject', 30, 1);
    expect(await purgeExpired(60)).toEqual({ secrets: 0, counters: 0 });
    expect(await countRateLimits()).toBe(1);
  });
});
