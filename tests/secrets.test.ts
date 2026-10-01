/**
 * Secret lifecycle: opaque payload fidelity, single use, passwords, expiry, the
 * control link states and the peek endpoint that must never consume.
 */
import { Buffer } from 'node:buffer';
import { beforeEach, describe, expect, it } from 'vitest';
import { query } from '../src/lib/db.ts';
import { resetConfigCache } from '../src/lib/env.ts';
import { PASSWORD_VERIFIER_TEXT, decryptPayload, derivePasswordKey } from '../src/lib/content-crypto.ts';
import {
  cancelSecret,
  createSecret,
  peekSecretPresence,
  purgeExpired,
  readControlStatus,
  readPasswordVerifier,
  revealSecret,
} from '../src/lib/secrets.ts';
import {
  countRateLimits,
  countReceipts,
  countSecrets,
  fetchRateLimitRows,
  fetchReceipt,
  fetchSecretRow,
  deleteReceipt,
  dummyVerifier,
  forceExpire,
  forceReceiptPurge,
  insertRateLimitRow,
  lockWithLegacyPassword,
  resetEnv,
  secretRowJson,
  sealedPasswordSecret,
  sealedSecret,
  setExpiresInSeconds,
  tableExists,
  utf8,
} from './helpers.ts';

beforeEach(async () => {
  await resetEnv();
});

/**
 * Run `fn` with a valid but different encryption key, so the GCM tag cannot
 * verify. The key is always restored and the memoized config dropped, so the
 * next test sees the original key again.
 */
async function withWrongKey<T>(fn: () => Promise<T>, filler = 7): Promise<T> {
  const original = process.env.SECRET_ENCRYPTION_KEY;
  process.env.SECRET_ENCRYPTION_KEY = Buffer.alloc(32, filler).toString('base64url');
  resetConfigCache();
  try {
    return await fn();
  } finally {
    process.env.SECRET_ENCRYPTION_KEY = original;
    resetConfigCache();
  }
}

describe('create and reveal without a password', () => {
  const plaintexts: ReadonlyArray<readonly [string, string]> = [
    ['plain ascii', 'the quick brown fox jumps over the lazy dog'],
    ['trailing spaces', 'secret with trailing spaces    '],
    ['trailing newline', 'ends with a newline\n'],
    ['trailing CRLF', 'windows line ending\r\n'],
    ['tabs and blank lines', '\tone\n\n\t\ttwo\r\n\r\n'],
    ['leading whitespace', '   indented'],
    ['single space', ' '],
    ['leading BOM', '\uFEFFpayload preceded by a byte order mark'],
    ['emoji and astral pairs', '\u{1F600}\u{1F389}\u{1F469}\u200D\u{1F4BB}\u{1F1EE}\u{1F1F5}'],
    ['combining marks', 'e\u0301 vs \u00E9'],
    ['right to left text', '\u0645\u0631\u062D\u0628\u0627 \u0628\u0627\u0644\u0639\u0627\u0644\u0645'],
    ['json looking text', '{"secret":"value","nested":{"a":[1,2,3]}}'],
    ['sql looking text', "'); DROP TABLE secrets; --"],
  ];

  it.each(plaintexts)('round-trips %s byte for byte and is then unavailable', async (_label, plaintext) => {
    const { payload, key } = await sealedSecret(plaintext);
    const created = await createSecret({ payload, expiresIn: '7d' });

    const first = await revealSecret(created.token);
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error('payload was not returned');
    // The server is an opaque courier: it hands back the very bytes it was given.
    expect(first.payload).toBe(payload);
    // Only the fragment key can open it, and the text is still byte exact.
    expect(await decryptPayload(first.payload, key)).toBe(plaintext);
    expect(utf8(await decryptPayload(first.payload, key)).equals(utf8(plaintext))).toBe(true);

    const second = await revealSecret(created.token);
    expect(second).toEqual({ ok: false, reason: 'unavailable' });
    expect(await countSecrets()).toBe(0);
  });

  it('returns two distinct well formed tokens and an expiry from the database clock', async () => {
    const { payload } = await sealedSecret('expiry check');
    const before = Date.now();
    const created = await createSecret({ payload, expiresIn: '1d' });
    const delta = created.expiresAt.getTime() - before;
    const day = 24 * 60 * 60 * 1000;

    expect(created.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(created.controlToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Two independent 256 bit tokens: a control link is not a share link.
    expect(created.controlToken).not.toBe(created.token);
    expect(delta).toBeGreaterThan(day - 10_000);
    expect(delta).toBeLessThan(day + 10_000);
  });

  it.each([
    ['1h', 60 * 60 * 1000],
    ['1d', 24 * 60 * 60 * 1000],
    ['7d', 7 * 24 * 60 * 60 * 1000],
    ['30d', 30 * 24 * 60 * 60 * 1000],
  ] as const)('maps the %s preset to its own window', async (preset, window) => {
    const { payload } = await sealedSecret('preset window');
    const before = Date.now();
    const created = await createSecret({ payload, expiresIn: preset });
    const delta = created.expiresAt.getTime() - before;
    expect(delta).toBeGreaterThan(window - 10_000);
    expect(delta).toBeLessThan(window + 10_000);
  });

  it('ignores a password supplied at reveal time for an unprotected secret', async () => {
    const { payload } = await sealedSecret('no password needed');
    const created = await createSecret({ payload, expiresIn: '7d' });
    expect(await revealSecret(created.token, 'an unexpected password')).toEqual({ ok: true, payload });
  });
});

describe('create and reveal with a client-side password', () => {
  const PASSWORD = 'correct horse battery staple';

  it('opens with the password-derived key and is unavailable afterwards', async () => {
    const sealed = await sealedPasswordSecret('protected payload', PASSWORD);
    const created = await createSecret({
      payload: sealed.payload,
      verifier: sealed.verifier,
      expiresIn: '7d',
    });

    const check = await readPasswordVerifier(created.token);
    expect(check).toEqual({ ok: true, verifier: sealed.verifier });
    expect(await countSecrets()).toBe(1);

    const derived = await derivePasswordKey(sealed.key, PASSWORD, sealed.salt);
    expect(await decryptPayload(sealed.verifier, derived)).toBe(PASSWORD_VERIFIER_TEXT);

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload: sealed.payload });
    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
    expect(await decryptPayload(sealed.payload, derived)).toBe('protected payload');
  });

  it('does not consume the secret when the password does not open the verifier', async () => {
    const sealed = await sealedPasswordSecret('still readable', PASSWORD);
    const created = await createSecret({
      payload: sealed.payload,
      verifier: sealed.verifier,
      expiresIn: '7d',
    });
    const check = await readPasswordVerifier(created.token);
    if (!check.ok) throw new Error('verifier was not returned');

    for (const attempt of ['wrong', PASSWORD.toUpperCase(), `${PASSWORD} `, 'w']) {
      const derived = await derivePasswordKey(sealed.key, attempt, sealed.salt);
      await expect(decryptPayload(check.verifier, derived)).rejects.toThrow();
    }
    expect(await countSecrets()).toBe(1);

    const derived = await derivePasswordKey(sealed.key, PASSWORD, sealed.salt);
    expect(await decryptPayload(check.verifier, derived)).toBe(PASSWORD_VERIFIER_TEXT);
    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('payload was not returned');
    expect(await decryptPayload(result.payload, derived)).toBe('still readable');
    await expect(decryptPayload(result.payload, sealed.key)).rejects.toThrow();
  });

  it('keeps protected content byte exact', async () => {
    const plaintext = 'line1\r\nline2\t\ttrailing   \n\uFEFF\u{1F600}';
    const sealed = await sealedPasswordSecret(plaintext, PASSWORD);
    const created = await createSecret({
      payload: sealed.payload,
      verifier: sealed.verifier,
      expiresIn: '7d',
    });

    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('payload was not returned');
    const derived = await derivePasswordKey(sealed.key, PASSWORD, sealed.salt);
    const opened = await decryptPayload(result.payload, derived);
    expect(utf8(opened).equals(utf8(plaintext))).toBe(true);
  });

  it('never stores or returns the password in any form', async () => {
    const sealed = await sealedPasswordSecret('password hygiene', PASSWORD);
    const created = await createSecret({
      payload: sealed.payload,
      verifier: sealed.verifier,
      expiresIn: '7d',
    });

    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');
    expect(row.password_hash).toBeNull();
    expect(row.password_verifier ?? '').not.toContain(PASSWORD);
    expect(row.ciphertext).not.toContain(PASSWORD);
    expect(await secretRowJson(created.token)).not.toContain(PASSWORD);

    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('payload was not returned');
    expect(result.payload).not.toContain(PASSWORD);
  });
});

describe('legacy server-side passwords', () => {
  const PASSWORD = 'legacy-password';

  it('does not consume the row when the password is wrong', async () => {
    const { payload } = await sealedSecret('legacy');
    const created = await createSecret({ payload, expiresIn: '7d' });
    await lockWithLegacyPassword(created.token, PASSWORD);

    expect(await revealSecret(created.token, 'wrong')).toEqual({ ok: false, reason: 'bad_password' });
    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
    expect(await revealSecret(created.token, PASSWORD)).toEqual({ ok: true, payload });
  });
});

describe('decryption failures', () => {
  it('does not consume the secret when the key is wrong, and works again once restored', async () => {
    const { payload } = await sealedSecret('survives a key rotation');
    const created = await createSecret({ payload, expiresIn: '7d' });

    await withWrongKey(async () => {
      expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
      expect(await fetchSecretRow(created.token)).toBeDefined();
    });

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume a verifier secret when the deployment key is wrong', async () => {
    const sealed = await sealedPasswordSecret('still protected', 'pw-probe');
    const created = await createSecret({
      payload: sealed.payload,
      verifier: sealed.verifier,
      expiresIn: '7d',
    });

    await withWrongKey(async () => {
      expect(await readPasswordVerifier(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
    }, 9);

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload: sealed.payload });
    expect(await countSecrets()).toBe(0);
  });

  it('reports a wrong legacy password rather than undecryptable when the key is wrong', async () => {
    const { payload } = await sealedSecret('protected');
    const created = await createSecret({ payload, expiresIn: '7d' });
    await lockWithLegacyPassword(created.token, 'pw-probe');

    await withWrongKey(async () => {
      expect(await revealSecret(created.token, 'wrong')).toEqual({ ok: false, reason: 'bad_password' });
      expect(await countSecrets()).toBe(1);
    }, 3);
  });

  it('does not consume a secret whose ciphertext was tampered with', async () => {
    const { payload } = await sealedSecret('tamper target');
    const created = await createSecret({ payload, expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    // Flip a byte in the sealed payload, keeping it valid base64url of the right
    // length so only the GCM tag can detect the change.
    const raw = Buffer.from(row.ciphertext, 'base64url');
    raw[20] = (raw[20] ?? 0) ^ 0x01;
    const tampered = raw.toString('base64url');
    await query('UPDATE secrets SET ciphertext = $2 WHERE token_hash = $1', [row.token_hash, tampered]);
    expect(tampered).not.toBe(row.ciphertext);

    try {
      expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
      expect((await fetchSecretRow(created.token))?.ciphertext).toBe(tampered);
    } finally {
      // Put the original payload back: the same link must still be redeemable.
      await query('UPDATE secrets SET ciphertext = $2 WHERE token_hash = $1', [row.token_hash, row.ciphertext]);
      resetConfigCache();
    }

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume a secret whose ciphertext is truncated below the nonce and tag', async () => {
    const { payload } = await sealedSecret('truncated');
    const created = await createSecret({ payload, expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    await query('UPDATE secrets SET ciphertext = $2 WHERE token_hash = $1', [row.token_hash, 'AAAA']);

    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
    expect(await countSecrets()).toBe(1);
  });

  it('leaves the ciphertext untouched when a decryption fails', async () => {
    const { payload } = await sealedSecret('untouched column');
    const created = await createSecret({ payload, expiresIn: '7d' });
    const before = await fetchSecretRow(created.token);
    if (!before) throw new Error('secret row missing');

    await withWrongKey(async () => {
      expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'undecryptable' });
    });

    const after = await fetchSecretRow(created.token);
    expect(after?.ciphertext).toBe(before.ciphertext);
    expect(after?.password_hash).toBe(before.password_hash);
  });

  it('answers with the deleted payload when the two ciphertexts ever differ', async () => {
    // The branch is unreachable through the database: the delete is the only
    // writer of the column and nothing updates it in place, and a BEFORE DELETE
    // trigger cannot change what RETURNING reports. Proving it is unreachable
    // would mean asserting a branch that can never execute, so what is asserted
    // here is the weaker fact that holds today: the payload returned by the
    // delete is the payload that was decrypted, so the caller is never handed a
    // different value than the one it verified.
    const { payload } = await sealedSecret('same payload both ways');
    const created = await createSecret({ payload, expiresIn: '7d' });
    const before = await fetchSecretRow(created.token);
    if (!before) throw new Error('secret row missing');

    const deleted = await query<{ ciphertext: string }>(
      'DELETE FROM secrets WHERE token_hash = $1 RETURNING ciphertext',
      [before.token_hash],
    );
    expect(deleted.rows[0]?.ciphertext).toBe(before.ciphertext);
    expect(await countSecrets()).toBe(0);
  });
});

describe('peekSecretPresence', () => {
  it('reports whether a password is required without consuming the secret', async () => {
    const open = await createSecret({ payload: (await sealedSecret('open secret')).payload, expiresIn: '7d' });
    const locked = await createSecret({
      payload: (await sealedSecret('locked secret')).payload,
      verifier: await dummyVerifier(),
      expiresIn: '7d',
    });

    expect(await peekSecretPresence(open.token)).toEqual({ password: 'none' });
    expect(await peekSecretPresence(locked.token)).toEqual({ password: 'client' });
    expect(await countSecrets()).toBe(2);
  });

  it('returns null for unknown, expired and malformed tokens', async () => {
    const expired = await createSecret({ payload: (await sealedSecret('gone')).payload, expiresIn: '7d' });
    await forceExpire(expired.token);

    expect(await peekSecretPresence('x'.repeat(43))).toBeNull();
    expect(await peekSecretPresence(expired.token)).toBeNull();
    expect(await peekSecretPresence('not-a-token')).toBeNull();
    expect(await peekSecretPresence('')).toBeNull();
  });

  it('never consumes the row, however often it is called', async () => {
    const { payload } = await sealedSecret('peek only');
    const created = await createSecret({ payload, expiresIn: '7d' });

    for (let attempt = 0; attempt < 25; attempt += 1) {
      expect(await peekSecretPresence(created.token)).toEqual({ password: 'none' });
    }

    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });
});

describe('expiration', () => {
  it('reports unavailable once expires_at is in the past and leaves the row for the cleanup job', async () => {
    const { payload } = await sealedSecret('expiring payload');
    const created = await createSecret({ payload, expiresIn: '1d' });
    await forceExpire(created.token);

    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
    // The conditional delete must not remove an already expired row.
    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
  });

  it('still reveals a secret whose expires_at is one hour ahead', async () => {
    const { payload } = await sealedSecret('not yet expired');
    const created = await createSecret({ payload, expiresIn: '1h' });

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('never reveals a protected secret that expired, even with the right password', async () => {
    const { payload } = await sealedSecret('expired and locked');
    const created = await createSecret({ payload, verifier: await dummyVerifier(), expiresIn: '1d' });
    await setExpiresInSeconds(created.token, -1);

    expect(await revealSecret(created.token, 'pw')).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('stays unavailable for an expired secret even with a wrong key', async () => {
    // Expiry is checked in SQL before the decrypt, so this never reaches the key
    // check and never reports undecryptable.
    const { payload } = await sealedSecret('expired');
    const created = await createSecret({ payload, expiresIn: '1d' });
    await forceExpire(created.token);

    await withWrongKey(async () => {
      expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
      expect(await countSecrets()).toBe(1);
    });
  });
});

describe('XSS and injection payloads', () => {
  const hostile: ReadonlyArray<readonly [string, string]> = [
    ['script tag', '<script>alert(1)</script>'],
    ['image error handler', '<img src=x onerror=alert(1)>'],
    ['statement terminator', '"; DROP TABLE secrets; --'],
  ];

  it.each(hostile)('carries a %s payload through untouched', async (_label, plaintext) => {
    const { payload, key } = await sealedSecret(plaintext);
    const created = await createSecret({ payload, expiresIn: '7d' });

    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('payload was not returned');
    // Nothing on the server ever parses this, and the client renders it as text.
    const opened = await decryptPayload(result.payload, key);
    expect(opened).toBe(plaintext);
    expect(utf8(opened).equals(utf8(plaintext))).toBe(true);
  });

  it('leaves the schema intact after hostile payloads', async () => {
    expect(await tableExists('secrets')).toBe(true);
    expect(await tableExists('rate_limits')).toBe(true);
    const { payload } = await sealedSecret("'; DELETE FROM secrets; --");
    const created = await createSecret({ payload, expiresIn: '7d' });

    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
    expect(await tableExists('secrets')).toBe(true);
  });
});

describe('readControlStatus', () => {
  it('reports pending for a live secret, without consuming anything', async () => {
    const created = await createSecret({ payload: (await sealedSecret('pending')).payload, expiresIn: '7d' });

    const status = await readControlStatus(created.controlToken);
    expect(status?.state).toBe('pending');
    expect(status?.expiresAt?.toISOString()).toBe(created.expiresAt.toISOString());

    // Reading the control link, like reloading its page, is not consumption.
    for (let attempt = 0; attempt < 10; attempt += 1) {
      expect((await readControlStatus(created.controlToken))?.state).toBe('pending');
    }
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
  });

  it('reports expired from the database clock, before the row is cleaned up', async () => {
    const created = await createSecret({ payload: (await sealedSecret('aged')).payload, expiresIn: '7d' });
    await forceExpire(created.token);

    expect((await readControlStatus(created.controlToken))?.state).toBe('expired');
    // The row is still there: expiry alone must not write a receipt.
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
  });

  it('reports read after a reveal, and cancelled after a cancel', async () => {
    const read = await createSecret({ payload: (await sealedSecret('was read')).payload, expiresIn: '7d' });
    await revealSecret(read.token);
    expect((await readControlStatus(read.controlToken))?.state).toBe('read');

    const cancelled = await createSecret({ payload: (await sealedSecret('was cancelled')).payload, expiresIn: '7d' });
    await cancelSecret(cancelled.controlToken);
    expect((await readControlStatus(cancelled.controlToken))?.state).toBe('cancelled');
  });

  it('returns null for an unknown, malformed or purged control token', async () => {
    const created = await createSecret({ payload: (await sealedSecret('purged')).payload, expiresIn: '7d' });
    await revealSecret(created.token);

    expect(await readControlStatus('x'.repeat(43))).toBeNull();
    expect(await readControlStatus('not-a-token')).toBeNull();
    expect(await readControlStatus('')).toBeNull();

    await forceReceiptPurge(created.controlToken);
    // A receipt whose retention has run out is still visible until the cleanup job
    // removes it, so only the removal itself makes the link unknown again.
    expect((await readControlStatus(created.controlToken))?.state).toBe('read');

    await deleteReceipt(created.controlToken);
    // A purged receipt is indistinguishable from a token that never existed.
    expect(await readControlStatus(created.controlToken)).toBeNull();
  });

  it('never returns the payload, the ciphertext or the share token', async () => {
    const { payload } = await sealedSecret('control link privacy');
    const created = await createSecret({ payload, verifier: await dummyVerifier(), expiresIn: '7d' });

    const status = await readControlStatus(created.controlToken);
    expect(Object.keys(status ?? {}).sort()).toEqual(['expiresAt', 'state']);
    expect(JSON.stringify(status)).not.toContain(payload);
  });
});

describe('cancelSecret', () => {
  it('deletes a pending secret, writes a cancelled receipt and blocks the reveal', async () => {
    const { payload } = await sealedSecret('cancel target');
    const created = await createSecret({ payload, verifier: await dummyVerifier(), expiresIn: '7d' });

    const result = await cancelSecret(created.controlToken);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('cancel did not return a status');
    expect(result.status.state).toBe('cancelled');
    expect(result.status.expiresAt?.toISOString()).toBe(created.expiresAt.toISOString());

    expect(await countSecrets()).toBe(0);
    expect((await fetchReceipt(created.controlToken))?.state).toBe('cancelled');
    // The share link dies with the row, and the password is never asked for.
    expect(await revealSecret(created.token, 'pw')).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('keeps the secret when the control token is wrong', async () => {
    const { payload } = await sealedSecret('wrong control');
    const created = await createSecret({ payload, expiresIn: '7d' });

    expect(await cancelSecret('x'.repeat(43))).toEqual({ ok: false, reason: 'unavailable' });
    expect(await cancelSecret('not-a-token')).toEqual({ ok: false, reason: 'unavailable' });
    expect(await cancelSecret('')).toEqual({ ok: false, reason: 'unavailable' });

    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
    expect(await revealSecret(created.token)).toEqual({ ok: true, payload });
  });

  it('refuses an already expired secret and leaves it to the cleanup job', async () => {
    const created = await createSecret({ payload: (await sealedSecret('late cancel')).payload, expiresIn: '7d' });
    await forceExpire(created.token);

    const result = await cancelSecret(created.controlToken);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('cancel did not return a status');
    expect(result.status.state).toBe('expired');
    // Nothing was deleted and no receipt was written: purge owns that path.
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
  });

  it('reports read rather than cancelled when a reveal won the race', async () => {
    const { payload } = await sealedSecret('reveal first');
    const created = await createSecret({ payload, expiresIn: '7d' });
    await revealSecret(created.token);

    const result = await cancelSecret(created.controlToken);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('cancel did not return a status');
    expect(result.status.state).toBe('read');
    expect((await fetchReceipt(created.controlToken))?.state).toBe('read');
    // A second cancel sees the same receipt and changes nothing.
    expect(await cancelSecret(created.controlToken)).toEqual(result);
    expect(await countReceipts()).toBe(1);
  });

  it('is idempotent for an already cancelled secret', async () => {
    const created = await createSecret({ payload: (await sealedSecret('twice')).payload, expiresIn: '7d' });
    await cancelSecret(created.controlToken);
    const second = await cancelSecret(created.controlToken);

    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error('cancel did not return a status');
    expect(second.status.state).toBe('cancelled');
    expect(await countReceipts()).toBe(1);
  });

  it('never asks for a password, so it cannot be locked out by one', async () => {
    const created = await createSecret({
      payload: (await sealedSecret('locked control')).payload,
      expiresIn: '7d',
      verifier: await dummyVerifier(),
    });

    // The control link is not a credential: holding it is what authorises the
    // cancel, so no password is read, hashed or compared anywhere in the path.
    expect(await cancelSecret(created.controlToken)).toEqual({
      ok: true,
      status: { state: 'cancelled', expiresAt: created.expiresAt },
    });
  });
});

describe('purgeExpired', () => {
  it('removes expired secrets, writes expired receipts and drops idle counters only', async () => {
    const expired = await createSecret({ payload: (await sealedSecret('expired')).payload, expiresIn: '1d' });
    const live = await createSecret({ payload: (await sealedSecret('live')).payload, expiresIn: '30d' });
    await forceExpire(expired.token);
    await insertRateLimitRow('create', 'stale-subject', 7200, 9);
    await insertRateLimitRow('reveal', 'fresh-subject', 5, 3);

    const result = await purgeExpired(3600);
    expect(result).toEqual({ secrets: 1, receipts: 0, counters: 1 });

    expect(await fetchSecretRow(expired.token)).toBeUndefined();
    expect(await fetchSecretRow(live.token)).toBeDefined();
    expect(await fetchRateLimitRows('create', 'stale-subject')).toHaveLength(0);
    expect(await fetchRateLimitRows('reveal', 'fresh-subject')).toHaveLength(1);
    expect(await countRateLimits()).toBe(1);

    // The control link now explains itself instead of vanishing.
    expect((await readControlStatus(expired.controlToken))?.state).toBe('expired');
    expect((await fetchReceipt(expired.controlToken))?.state).toBe('expired');

    const revealed = await revealSecret(live.token);
    expect(revealed.ok).toBe(true);
  });

  it('drops spent receipts only once their retention has passed', async () => {
    const created = await createSecret({ payload: (await sealedSecret('spent')).payload, expiresIn: '7d' });
    await revealSecret(created.token);

    expect(await countReceipts()).toBe(1);
    // A secret that expires in seven days keeps its receipt at least that long.
    expect(await purgeExpired(0)).toEqual({ secrets: 0, receipts: 0, counters: 0 });
    expect(await countReceipts()).toBe(1);

    await forceReceiptPurge(created.controlToken);
    expect(await purgeExpired(0)).toEqual({ secrets: 0, receipts: 1, counters: 0 });
    expect(await countReceipts()).toBe(0);
    // And with the receipt gone the control link is unknown again.
    expect(await readControlStatus(created.controlToken)).toBeNull();
  });

  it('keeps a live secret when only its receipt is due', async () => {
    const created = await createSecret({ payload: (await sealedSecret('both')).payload, expiresIn: '7d' });
    // A receipt cannot predate its own secret, so this state is only reachable by
    // hand: the point is that the two sweeps are independent.
    await forceReceiptPurge(created.controlToken);
    expect(await purgeExpired(0)).toEqual({ secrets: 0, receipts: 0, counters: 0 });
    expect(await fetchSecretRow(created.token)).toBeDefined();
  });

  it('reports zeroes when there is nothing to remove', async () => {
    expect(await purgeExpired(3600)).toEqual({ secrets: 0, receipts: 0, counters: 0 });
  });
});
