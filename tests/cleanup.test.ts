/**
 * Periodic maintenance: `purgeExpired` is the in-process twin of
 * `scripts/cleanup.mjs`, and the same invariants must hold for both.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { hashToken } from '../src/lib/crypto.ts';
import { query } from '../src/lib/db.ts';
import { createSecret, purgeExpired, revealSecret } from '../src/lib/secrets.ts';
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
