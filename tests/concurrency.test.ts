/**
 * Concurrent consumption.
 *
 * These are the tests that matter most: a one-time secret must be readable by
 * exactly one caller no matter how many requests arrive at the same instant.
 */
import { Buffer } from 'node:buffer';
import { beforeEach, describe, expect, it } from 'vitest';
import { hashToken } from '../src/lib/crypto.ts';
import { withClient } from '../src/lib/db.ts';
import { resetConfigCache } from '../src/lib/env.ts';
import { createSecret, revealSecret } from '../src/lib/secrets.ts';
import { countSecrets, resetEnv } from './helpers.ts';

beforeEach(async () => {
  await resetEnv();
});

function countWinners(results: ReadonlyArray<{ readonly ok: boolean }>): number {
  return results.filter((result) => result.ok).length;
}

describe('parallel revealSecret', () => {
  it('gives the content to exactly one of eight concurrent reveals', async () => {
    const created = await createSecret({ secret: 'read me once', expiresInDays: 7 });

    const results = await Promise.all(
      Array.from({ length: 8 }, () => revealSecret(created.token)),
    );

    const winners = results.filter((result) => result.ok);
    const losers = results.filter((result) => !result.ok);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(7);
    for (const loser of losers) expect(loser).toEqual({ ok: false, reason: 'unavailable' });

    if (!winners[0]?.ok) throw new Error('no winner');
    expect(winners[0].secret).toBe('read me once');
    expect(await countSecrets()).toBe(0);
    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('holds with twenty concurrent reveals', async () => {
    const created = await createSecret({ secret: 'single use', expiresInDays: 7 });

    const results = await Promise.all(
      Array.from({ length: 20 }, () => revealSecret(created.token)),
    );

    expect(countWinners(results)).toBe(1);
    expect(await countSecrets()).toBe(0);
  });

  it('gives the content to exactly one of three concurrent reveals on a protected secret', async () => {
    const created = await createSecret({
      secret: 'protected single use',
      expiresInDays: 7,
      password: 'p4ssw0rd',
    });

    const results = await Promise.all(
      Array.from({ length: 3 }, () => revealSecret(created.token, 'p4ssw0rd')),
    );

    expect(countWinners(results)).toBe(1);
    for (const loser of results.filter((result) => !result.ok)) {
      expect(loser).toEqual({ ok: false, reason: 'unavailable' });
    }
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume the secret when every concurrent attempt uses a wrong password', async () => {
    const created = await createSecret({
      secret: 'guarded payload',
      expiresInDays: 7,
      password: 'p4ssw0rd',
    });

    const results = await Promise.all(
      Array.from({ length: 3 }, (_unused, index) => revealSecret(created.token, `wrong-${index}`)),
    );

    expect(countWinners(results)).toBe(0);
    for (const result of results) expect(result).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
    expect(await revealSecret(created.token, 'p4ssw0rd')).toEqual({
      ok: true,
      secret: 'guarded payload',
    });
  });

  it('does not let a winning reveal of a different secret be affected by a loser', async () => {
    const first = await createSecret({ secret: 'first secret', expiresInDays: 7 });
    const second = await createSecret({ secret: 'second secret', expiresInDays: 7 });

    const results = await Promise.all([
      revealSecret(first.token),
      revealSecret(second.token),
      revealSecret(first.token),
      revealSecret(second.token),
    ]);

    const winners = results.filter((result) => result.ok);
    expect(winners).toHaveLength(2);
    expect(winners.map((winner) => (winner.ok ? winner.secret : '')).sort()).toEqual([
      'first secret',
      'second secret',
    ]);
    expect(await countSecrets()).toBe(0);
  });

  it('still gives the content to exactly one caller when decryption precedes the delete', async () => {
    // Decryption now happens before the delete, so the race is between the
    // deletes of N callers that all decrypted successfully. The invariant is
    // unchanged: one winner, and the row exists for nobody afterwards.
    const created = await createSecret({ secret: 'decrypted before deleted', expiresInDays: 7 });

    const results = await Promise.all(
      Array.from({ length: 20 }, () => revealSecret(created.token)),
    );

    const winners = results.filter((result) => result.ok);
    expect(winners).toHaveLength(1);
    expect(winners[0]?.ok === true ? winners[0].secret : '').toBe('decrypted before deleted');
    for (const loser of results.filter((result) => !result.ok)) {
      expect(loser).toEqual({ ok: false, reason: 'unavailable' });
    }
    expect(await countSecrets()).toBe(0);
  });

  it('leaves the row untouched when the key is wrong, however many callers race', async () => {
    // None of the callers may reach the delete, so the secret survives and is
    // readable again once the key is restored.
    const originalKey = process.env.SECRET_ENCRYPTION_KEY;
    const created = await createSecret({ secret: 'key comes back', expiresInDays: 7 });

    process.env.SECRET_ENCRYPTION_KEY = Buffer.alloc(32, 5).toString('base64url');
    resetConfigCache();
    try {
      const results = await Promise.all(Array.from({ length: 10 }, () => revealSecret(created.token)));
      for (const result of results) expect(result).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
    } finally {
      process.env.SECRET_ENCRYPTION_KEY = originalKey;
      resetConfigCache();
    }

    const results = await Promise.all(Array.from({ length: 10 }, () => revealSecret(created.token)));
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(await countSecrets()).toBe(0);
  });
});

describe('raw DELETE ... RETURNING across two pool clients', () => {
  it('lets the database hand the row to a single client', async () => {
    const created = await createSecret({ secret: 'raw race', expiresInDays: 7 });
    const tokenHash = hashToken(created.token);
    const statement = 'DELETE FROM secrets WHERE token_hash = $1 RETURNING ciphertext';

    const [left, right] = await Promise.all([
      withClient((client) => client.query<{ ciphertext: string }>(statement, [tokenHash])),
      withClient((client) => client.query<{ ciphertext: string }>(statement, [tokenHash])),
    ]);

    // Which client wins the race is not deterministic; only the count is.
    const winners = [left, right].filter((result) => result.rowCount === 1);
    expect(winners).toHaveLength(1);
    expect([left.rowCount ?? 0, right.rowCount ?? 0].reduce((sum, count) => sum + count, 0)).toBe(1);
    expect(await countSecrets()).toBe(0);
  });

  it('deletes nothing when the conditional predicate no longer holds', async () => {
    const created = await createSecret({ secret: 'already expired', expiresInDays: 7 });
    const tokenHash = hashToken(created.token);
    await withClient((client) =>
      client.query(`UPDATE secrets SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, [
        tokenHash,
      ]),
    );

    const result = await withClient((client) =>
      client.query('DELETE FROM secrets WHERE token_hash = $1 AND expires_at > now() RETURNING ciphertext', [
        tokenHash,
      ]),
    );

    expect(result.rowCount).toBe(0);
    expect(await countSecrets()).toBe(1);
  });
});

describe('concurrent creation', () => {
  it('creates independent, uniquely tokenized secrets', async () => {
    const created = await Promise.all(
      Array.from({ length: 20 }, (_unused, index) =>
        createSecret({ secret: `payload number ${index}`, expiresInDays: 7 }),
      ),
    );

    expect(new Set(created.map((entry) => entry.token)).size).toBe(20);
    expect(await countSecrets()).toBe(20);

    const revealed = await Promise.all(created.map((entry) => revealSecret(entry.token)));
    expect(countWinners(revealed)).toBe(20);
    expect(await countSecrets()).toBe(0);
  });
});
