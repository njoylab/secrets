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
import { cancelSecret, createSecret, readControlStatus, revealSecret } from '../src/lib/secrets.ts';
import {
  countReceipts,
  countSecrets,
  dummyVerifier,
  fetchReceipt,
  lockWithLegacyPassword,
  resetEnv,
  sealedSecret,
} from './helpers.ts';

beforeEach(async () => {
  await resetEnv();
});

function countWinners(results: ReadonlyArray<{ readonly ok: boolean }>): number {
  return results.filter((result) => result.ok).length;
}

describe('parallel revealSecret', () => {
  it('gives the content to exactly one of eight concurrent reveals', async () => {
    const { payload } = await sealedSecret('read me once');
    const created = await createSecret({ payload, expiresIn: '7d' });

    const results = await Promise.all(
      Array.from({ length: 8 }, () => revealSecret(created.token)),
    );

    const winners = results.filter((result) => result.ok);
    const losers = results.filter((result) => !result.ok);
    expect(winners).toHaveLength(1);
    expect(losers).toHaveLength(7);
    for (const loser of losers) expect(loser).toEqual({ ok: false, reason: 'unavailable' });

    if (!winners[0]?.ok) throw new Error('no winner');
    expect(winners[0].payload).toBe(payload);
    expect(await countSecrets()).toBe(0);
    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('holds with twenty concurrent reveals', async () => {
    const created = await createSecret({ payload: (await sealedSecret('single use')).payload, expiresIn: '7d' });

    const results = await Promise.all(
      Array.from({ length: 20 }, () => revealSecret(created.token)),
    );

    expect(countWinners(results)).toBe(1);
    expect(await countSecrets()).toBe(0);
  });

  it('gives the content to exactly one of three concurrent reveals on a protected secret', async () => {
    const created = await createSecret({
      payload: (await sealedSecret('protected single use')).payload,
      verifier: await dummyVerifier(),
      expiresIn: '7d',
    });

    const results = await Promise.all(Array.from({ length: 3 }, () => revealSecret(created.token)));

    expect(countWinners(results)).toBe(1);
    for (const loser of results.filter((result) => !result.ok)) {
      expect(loser).toEqual({ ok: false, reason: 'unavailable' });
    }
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume the secret when every concurrent attempt uses a wrong legacy password', async () => {
    const { payload } = await sealedSecret('guarded payload');
    const created = await createSecret({ payload, expiresIn: '7d' });
    await lockWithLegacyPassword(created.token, 'p4ssw0rd');

    const results = await Promise.all(
      Array.from({ length: 3 }, (_unused, index) => revealSecret(created.token, `wrong-${index}`)),
    );

    expect(countWinners(results)).toBe(0);
    for (const result of results) expect(result).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
    expect(await revealSecret(created.token, 'p4ssw0rd')).toEqual({ ok: true, payload });
  });

  it('does not let a winning reveal of a different secret be affected by a loser', async () => {
    const firstPayload = (await sealedSecret('first secret')).payload;
    const secondPayload = (await sealedSecret('second secret')).payload;
    const first = await createSecret({ payload: firstPayload, expiresIn: '7d' });
    const second = await createSecret({ payload: secondPayload, expiresIn: '7d' });

    const results = await Promise.all([
      revealSecret(first.token),
      revealSecret(second.token),
      revealSecret(first.token),
      revealSecret(second.token),
    ]);

    const winners = results.filter((result) => result.ok);
    expect(winners).toHaveLength(2);
    expect(winners.map((winner) => (winner.ok ? winner.payload : '')).sort()).toEqual(
      [firstPayload, secondPayload].sort(),
    );
    expect(await countSecrets()).toBe(0);
  });

  it('still gives the content to exactly one caller when decryption precedes the delete', async () => {
    // Decryption now happens before the delete, so the race is between the
    // deletes of N callers that all decrypted successfully. The invariant is
    // unchanged: one winner, and the row exists for nobody afterwards.
    const { payload } = await sealedSecret('decrypted before deleted');
    const created = await createSecret({ payload, expiresIn: '7d' });

    const results = await Promise.all(
      Array.from({ length: 20 }, () => revealSecret(created.token)),
    );

    const winners = results.filter((result) => result.ok);
    expect(winners).toHaveLength(1);
    expect(winners[0]?.ok === true ? winners[0].payload : '').toBe(payload);
    for (const loser of results.filter((result) => !result.ok)) {
      expect(loser).toEqual({ ok: false, reason: 'unavailable' });
    }
    expect(await countSecrets()).toBe(0);
  });

  it('leaves the row untouched when the key is wrong, however many callers race', async () => {
    // None of the callers may reach the delete, so the secret survives and is
    // readable again once the key is restored.
    const originalKey = process.env.SECRET_ENCRYPTION_KEY;
    const { payload } = await sealedSecret('key comes back');
    const created = await createSecret({ payload, expiresIn: '7d' });

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
    const created = await createSecret({ payload: (await sealedSecret('raw race')).payload, expiresIn: '7d' });
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
    const created = await createSecret({ payload: (await sealedSecret('already expired')).payload, expiresIn: '7d' });
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
      Array.from({ length: 20 }, async (_unused, index) =>
        createSecret({
          payload: (await sealedSecret(`payload number ${index}`)).payload,
          expiresIn: '7d',
        }),
      ),
    );

    expect(new Set(created.map((entry) => entry.token)).size).toBe(20);
    // The control tokens are independent of the share tokens, so no two links collide.
    expect(new Set(created.map((entry) => entry.controlToken)).size).toBe(20);
    expect(await countSecrets()).toBe(20);

    const revealed = await Promise.all(created.map((entry) => revealSecret(entry.token)));
    expect(countWinners(revealed)).toBe(20);
    expect(await countSecrets()).toBe(0);
  });
});

describe('concurrent cancel against reveal', () => {
  it('lets exactly one of the two closers win, and records what happened', async () => {
    // A cancel and a reveal race for the same row. Both run the same shape of
    // transaction and neither holds a lock across a password check, so the
    // database decides and the receipt records the winner. Rounds are independent,
    // so each one starts from an empty table.
    for (let round = 0; round < 12; round += 1) {
      await resetEnv();
      const { payload } = await sealedSecret(`race ${round}`);
      const created = await createSecret({ payload, expiresIn: '7d' });

      const [cancelled, revealed] = await Promise.all([
        cancelSecret(created.controlToken),
        revealSecret(created.token),
      ]);

      // One of the two must have removed the row, and it wrote exactly one receipt.
      expect(await countSecrets()).toBe(0);
      expect(await countReceipts()).toBe(1);

      const receipt = await fetchReceipt(created.controlToken);
      if (!receipt) throw new Error('receipt missing');

      if (receipt.state === 'cancelled') {
        // The cancel won, so the reveal got nothing at all.
        expect(cancelled.ok).toBe(true);
        if (cancelled.ok) expect(cancelled.status.state).toBe('cancelled');
        expect(revealed).toEqual({ ok: false, reason: 'unavailable' });
      } else {
        // The reveal won, and it is the only one that ever had the payload.
        expect(cancelled.ok).toBe(true);
        if (cancelled.ok) expect(cancelled.status.state).toBe('read');
        expect(revealed).toEqual({ ok: true, payload });
      }

      expect((await readControlStatus(created.controlToken))?.state).toBe(receipt.state);
    }
  });

  it('reports the winning state when many cancels race a reveal', async () => {
    const { payload } = await sealedSecret('crowded race');
    const created = await createSecret({ payload, expiresIn: '7d' });

    const [firstCancel, secondCancel, revealed, thirdCancel] = await Promise.all([
      cancelSecret(created.controlToken),
      cancelSecret(created.controlToken),
      revealSecret(created.token),
      cancelSecret(created.controlToken),
    ]);

    const cancels = [firstCancel, secondCancel, thirdCancel];
    const receipt = await fetchReceipt(created.controlToken);
    if (!receipt) throw new Error('receipt missing');

    // Every cancel answers with the authoritative state, and they all agree with
    // the receipt the winning closer wrote.
    for (const result of cancels) {
      expect(result.ok).toBe(true);
      if (result.ok) expect(result.status.state).toBe(receipt.state);
    }

    // Whichever closer won, the reveal only succeeds if it was the reader.
    if (receipt.state === 'read') {
      expect(revealed).toEqual({ ok: true, payload });
    } else {
      expect(revealed).toEqual({ ok: false, reason: 'unavailable' });
    }

    expect(await countReceipts()).toBe(1);
    expect(await countSecrets()).toBe(0);
  });

  it('never writes two receipts for the same control token', async () => {
    const { payload } = await sealedSecret('one receipt');
    const created = await createSecret({ payload, expiresIn: '7d' });

    await Promise.all([
      cancelSecret(created.controlToken),
      cancelSecret(created.controlToken),
      cancelSecret(created.controlToken),
      revealSecret(created.token),
    ]);

    // A second insert would have violated the primary key and rolled the row back.
    expect(await countReceipts()).toBe(1);
    expect(await countSecrets()).toBe(0);
    expect((await fetchReceipt(created.controlToken))?.state).toMatch(/^(read|cancelled)$/);
  });
});

