/**
 * Secret lifecycle: opaque payload fidelity, single use, passwords, expiry, the
 * control link states and the peek endpoint that must never consume.
 */
import { Buffer } from 'node:buffer';
import { beforeEach, describe, expect, it } from 'vitest';
import { query } from '../src/lib/db.ts';
import { resetConfigCache } from '../src/lib/env.ts';
import { decryptPayload, deriveSecretKeys, encodeAuthKey } from '../src/lib/content-crypto.ts';
import {
  cancelSecret,
  createSecret,
  peekSecretPresence,
  readControlStatus,
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
  expectedStoredAuthHash,
  TEST_AUTH_HASH,
  TEST_AUTH_KEY,
  forceExpire,
  forceReceiptPurge,
  insertRateLimitRow,
  purgeExpired,
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
    const { payload, contentKey: key } = await sealedSecret(plaintext);
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    const first = await revealSecret(created.token, TEST_AUTH_KEY);
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error('payload was not returned');
    // The server is an opaque courier: it hands back the very bytes it was given.
    expect(first.payload).toBe(payload);
    // Only the fragment key can open it, and the text is still byte exact.
    expect(await decryptPayload(first.payload, key)).toBe(plaintext);
    expect(utf8(await decryptPayload(first.payload, key)).equals(utf8(plaintext))).toBe(true);

    const second = await revealSecret(created.token, TEST_AUTH_KEY);
    expect(second).toEqual({ ok: false, reason: 'unavailable' });
    expect(await countSecrets()).toBe(0);
  });

  it('returns two distinct well formed tokens and an expiry from the database clock', async () => {
    const { payload } = await sealedSecret('expiry check');
    const before = Date.now();
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '1d' });
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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: preset });
    const delta = created.expiresAt.getTime() - before;
    expect(delta).toBeGreaterThan(window - 10_000);
    expect(delta).toBeLessThan(window + 10_000);
  });

  it('opens with the auth key derived from the fragment key alone', async () => {
    const sealed = await sealedSecret('derived without a password');
    const created = await createSecret({ payload: sealed.payload, authHash: sealed.authHash, expiresIn: '7d' });
    const result = await revealSecret(created.token, sealed.authKey);
    if (!result.ok) throw new Error('payload was not returned');
    expect(await decryptPayload(result.payload, sealed.contentKey)).toBe('derived without a password');
  });

  it('refuses a missing, malformed or wrong key without consuming', async () => {
    const sealed = await sealedSecret('wrong key survives');
    const created = await createSecret({ payload: sealed.payload, authHash: sealed.authHash, expiresIn: '7d' });
    // A tampered but well formed fragment key derives a different auth key.
    const tampered = new Uint8Array(sealed.key);
    tampered[0] = (tampered[0] ?? 0) ^ 0x01;
    const tamperedAuth = encodeAuthKey((await deriveSecretKeys(tampered, null, null)).authKey);

    for (const authKey of [undefined, null, 42, '', 'short', `${sealed.authKey}x`, `${sealed.authKey.slice(0, 42)}=`,
      TEST_AUTH_KEY, tamperedAuth, sealed.authHash, encodeAuthKey(sealed.contentKey)]) {
      expect(await revealSecret(created.token, authKey)).toEqual({ ok: false, reason: 'bad_key' });
    }
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
    expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: true, payload: sealed.payload });
  });

  it('rejects a non-canonical spelling of the right auth key', async () => {
    const sealed = await sealedSecret('canonical only');
    const created = await createSecret({ payload: sealed.payload, authHash: sealed.authHash, expiresIn: '7d' });
    // The last character carries two unused bits; setting them decodes to the
    // same bytes under a lenient decoder, and must still be refused.
    const last = sealed.authKey.at(-1) ?? 'A';
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const variant = sealed.authKey.slice(0, -1) + alphabet[(alphabet.indexOf(last) & ~3) | 1];
    expect(await revealSecret(created.token, variant)).toEqual({ ok: false, reason: 'bad_key' });
    expect(await countSecrets()).toBe(1);
  });
});

describe('create and reveal with a client-side password', () => {
  const PASSWORD = 'correct horse battery staple';

  async function createProtected(text: string) {
    const sealed = await sealedPasswordSecret(text, PASSWORD);
    const created = await createSecret({
      payload: sealed.payload,
      authHash: sealed.authHash,
      passwordProtected: true,
      expiresIn: '7d',
    });
    return { sealed, created };
  }

  it('opens with the password-derived keys and is unavailable afterwards', async () => {
    const { sealed, created } = await createProtected('protected payload');
    expect(await peekSecretPresence(created.token)).toEqual({ password: 'client' });

    const keys = await deriveSecretKeys(sealed.key, PASSWORD, sealed.salt);
    expect(encodeAuthKey(keys.authKey)).toBe(sealed.authKey);
    expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: true, payload: sealed.payload });
    expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: false, reason: 'unavailable' });
    expect(await decryptPayload(sealed.payload, keys.contentKey)).toBe('protected payload');
  });

  it('does not consume the secret on a wrong password, however many attempts', async () => {
    const { sealed, created } = await createProtected('still readable');

    for (const attempt of ['wrong', PASSWORD.toUpperCase(), `${PASSWORD} `, 'w']) {
      const keys = await deriveSecretKeys(sealed.key, attempt, sealed.salt);
      expect(await revealSecret(created.token, encodeAuthKey(keys.authKey))).toEqual({
        ok: false,
        reason: 'bad_password',
      });
    }
    // The fragment key alone, without the password, is not enough either.
    const withoutPassword = await deriveSecretKeys(sealed.key, null, null);
    expect(await revealSecret(created.token, encodeAuthKey(withoutPassword.authKey))).toEqual({
      ok: false,
      reason: 'bad_password',
    });
    expect(await revealSecret(created.token, undefined)).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);

    const result = await revealSecret(created.token, sealed.authKey);
    if (!result.ok) throw new Error('payload was not returned');
    expect(await decryptPayload(result.payload, sealed.contentKey)).toBe('still readable');
    await expect(decryptPayload(result.payload, sealed.key)).rejects.toThrow();
  });

  it('refuses the right password with a tampered fragment key', async () => {
    const { sealed, created } = await createProtected('fragment matters');
    const tampered = new Uint8Array(sealed.key);
    tampered[5] = (tampered[5] ?? 0) ^ 0x80;
    const keys = await deriveSecretKeys(tampered, PASSWORD, sealed.salt);
    expect(await revealSecret(created.token, encodeAuthKey(keys.authKey))).toEqual({
      ok: false,
      reason: 'bad_password',
    });
    expect(await countSecrets()).toBe(1);
  });

  it('keeps protected content byte exact', async () => {
    const plaintext = 'line1\r\nline2\t\ttrailing   \n﻿\u{1F600}';
    const { sealed, created } = await createProtected(plaintext);

    const result = await revealSecret(created.token, sealed.authKey);
    if (!result.ok) throw new Error('payload was not returned');
    const opened = await decryptPayload(result.payload, sealed.contentKey);
    expect(utf8(opened).equals(utf8(plaintext))).toBe(true);
  });

  it('never stores the password, the auth key or any key in any form', async () => {
    const { sealed, created } = await createProtected('password hygiene');

    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');
    expect(row.has_password).toBe(true);
    expect(row.auth_hash).toBe(expectedStoredAuthHash(sealed.authHash));
    const json = await secretRowJson(created.token);
    for (const forbidden of [PASSWORD, sealed.authKey, sealed.keyText, encodeAuthKey(sealed.contentKey)]) {
      expect(json.includes(forbidden)).toBe(false);
    }

    const result = await revealSecret(created.token, sealed.authKey);
    if (!result.ok) throw new Error('payload was not returned');
    expect(result.payload).not.toContain(PASSWORD);
  });
});

describe('decryption failures', () => {
  it('does not consume the secret when the key is wrong, and works again once restored', async () => {
    const { payload } = await sealedSecret('survives a key rotation');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    await withWrongKey(async () => {
      expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
      expect(await fetchSecretRow(created.token)).toBeDefined();
    });

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume a password secret when the deployment key is wrong', async () => {
    const sealed = await sealedPasswordSecret('still protected', 'pw-probe');
    const created = await createSecret({
      payload: sealed.payload,
      authHash: sealed.authHash,
      passwordProtected: true,
      expiresIn: '7d',
    });

    await withWrongKey(async () => {
      expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
    }, 9);

    expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: true, payload: sealed.payload });
    expect(await countSecrets()).toBe(0);
  });

  it('reports a wrong deployment key as undecryptable, not as a password error, even with a wrong password', async () => {
    const sealed = await sealedPasswordSecret('wrong deployment key', 'pw-right');
    const wrong = await sealedPasswordSecret('wrong deployment key', 'pw-wrong');
    const created = await createSecret({
      payload: sealed.payload,
      authHash: sealed.authHash,
      passwordProtected: true,
      expiresIn: '7d',
    });

    await withWrongKey(async () => {
      for (const authKey of [sealed.authKey, wrong.authKey, TEST_AUTH_KEY, 'not-a-key']) {
        expect(await revealSecret(created.token, authKey)).toEqual({ ok: false, reason: 'undecryptable' });
      }
      expect(await countSecrets()).toBe(1);
    }, 11);

    expect(await revealSecret(created.token, wrong.authKey)).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
    expect(await revealSecret(created.token, sealed.authKey)).toEqual({ ok: true, payload: sealed.payload });
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume a secret whose ciphertext was tampered with', async () => {
    const { payload } = await sealedSecret('tamper target');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
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
      expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'undecryptable' });
      expect(await countSecrets()).toBe(1);
      expect((await fetchSecretRow(created.token))?.ciphertext).toBe(tampered);
    } finally {
      // Put the original payload back: the same link must still be redeemable.
      await query('UPDATE secrets SET ciphertext = $2 WHERE token_hash = $1', [row.token_hash, row.ciphertext]);
      resetConfigCache();
    }

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('does not consume a secret whose ciphertext is truncated below the nonce and tag', async () => {
    const { payload } = await sealedSecret('truncated');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    await query('UPDATE secrets SET ciphertext = $2 WHERE token_hash = $1', [row.token_hash, 'AAAA']);

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'undecryptable' });
    expect(await countSecrets()).toBe(1);
  });

  it('leaves the ciphertext untouched when a decryption fails', async () => {
    const { payload } = await sealedSecret('untouched column');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
    const before = await fetchSecretRow(created.token);
    if (!before) throw new Error('secret row missing');

    await withWrongKey(async () => {
      expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'undecryptable' });
    });

    const after = await fetchSecretRow(created.token);
    expect(after?.ciphertext).toBe(before.ciphertext);
    expect(after?.auth_hash).toBe(before.auth_hash);
  });
});

describe('peekSecretPresence', () => {
  it.each([
    ['a missing auth hash', 'auth_hash = NULL'],
    ['a malformed auth hash', "auth_hash = 'unsupported'"],
    ['a missing password flag', 'has_password = NULL'],
  ])('cannot hold a row with %s', async (_label, assignment) => {
    const created = await createSecret({
      authHash: TEST_AUTH_HASH,
      payload: (await sealedSecret('incomplete record')).payload,
      expiresIn: '7d',
    });
    const row = await fetchSecretRow(created.token);
    // The schema itself refuses incomplete rows, so no legacy shape can exist.
    await expect(query(`UPDATE secrets SET ${assignment} WHERE token_hash = $1`, [row!.token_hash])).rejects.toThrow();
    expect(await secretRowJson(created.token)).toContain(expectedStoredAuthHash(TEST_AUTH_HASH));
  });

  it('reports whether a password is required without consuming the secret', async () => {
    const open = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('open secret')).payload, expiresIn: '7d' });
    const locked = await createSecret({
      authHash: TEST_AUTH_HASH,
      payload: (await sealedSecret('locked secret')).payload,
      passwordProtected: true,
      expiresIn: '7d',
    });

    expect(await peekSecretPresence(open.token)).toEqual({ password: 'none' });
    expect(await peekSecretPresence(locked.token)).toEqual({ password: 'client' });
    expect(await countSecrets()).toBe(2);
  });

  it('returns null for unknown, expired and malformed tokens', async () => {
    const expired = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('gone')).payload, expiresIn: '7d' });
    await forceExpire(expired.token);

    expect(await peekSecretPresence('x'.repeat(43))).toBeNull();
    expect(await peekSecretPresence(expired.token)).toBeNull();
    expect(await peekSecretPresence('not-a-token')).toBeNull();
    expect(await peekSecretPresence('')).toBeNull();
  });

  it('never consumes the row, however often it is called', async () => {
    const { payload } = await sealedSecret('peek only');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    for (let attempt = 0; attempt < 25; attempt += 1) {
      expect(await peekSecretPresence(created.token)).toEqual({ password: 'none' });
    }

    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });
});

describe('expiration', () => {
  it('reports unavailable once expires_at is in the past and leaves the row for the cleanup job', async () => {
    const { payload } = await sealedSecret('expiring payload');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '1d' });
    await forceExpire(created.token);

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'unavailable' });
    // The conditional delete must not remove an already expired row.
    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
  });

  it('still reveals a secret whose expires_at is one hour ahead', async () => {
    const { payload } = await sealedSecret('not yet expired');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '1h' });

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
  });

  it('never reveals a protected secret that expired, even with the right proof', async () => {
    const { payload } = await sealedSecret('expired and locked');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, passwordProtected: true, expiresIn: '1d' });
    await setExpiresInSeconds(created.token, -1);

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('stays unavailable for an expired secret even with a wrong key', async () => {
    // Expiry is checked in SQL before the decrypt, so this never reaches the key
    // check and never reports undecryptable.
    const { payload } = await sealedSecret('expired');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '1d' });
    await forceExpire(created.token);

    await withWrongKey(async () => {
      expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: false, reason: 'unavailable' });
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
    const { payload, contentKey: key } = await sealedSecret(plaintext);
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    const result = await revealSecret(created.token, TEST_AUTH_KEY);
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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
    expect(await countSecrets()).toBe(0);
    expect(await tableExists('secrets')).toBe(true);
  });
});

describe('readControlStatus', () => {
  it('reports pending for a live secret, without consuming anything', async () => {
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('pending')).payload, expiresIn: '7d' });

    const status = await readControlStatus(created.controlToken);
    expect(status?.state).toBe('pending');
    expect(status?.expiresAt?.toISOString()).toBe(created.expiresAt.toISOString());
    // A live secret knows when it was made and has not closed yet.
    expect(status?.createdAt).toBeInstanceOf(Date);
    expect(status?.createdAt!.getTime()).toBeLessThanOrEqual(status!.expiresAt!.getTime());
    expect(status?.closedAt).toBeNull();

    // Reading the control link, like reloading its page, is not consumption.
    for (let attempt = 0; attempt < 10; attempt += 1) {
      expect((await readControlStatus(created.controlToken))?.state).toBe('pending');
    }
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
  });

  it('reports expired from the database clock, before the row is cleaned up', async () => {
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('aged')).payload, expiresIn: '7d' });
    await forceExpire(created.token);

    expect((await readControlStatus(created.controlToken))?.state).toBe('expired');
    // The row is still there: expiry alone must not write a receipt.
    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
  });

  it('reports read after a reveal, and cancelled after a cancel', async () => {
    const read = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('was read')).payload, expiresIn: '7d' });
    await revealSecret(read.token, TEST_AUTH_KEY);
    const afterRead = await readControlStatus(read.controlToken);
    expect(afterRead?.state).toBe('read');
    // The row is gone, so the receipt supplies the closing instant and the
    // creation instant is no longer available.
    expect(afterRead?.closedAt).toBeInstanceOf(Date);
    expect(afterRead?.createdAt).toBeNull();

    const cancelled = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('was cancelled')).payload, expiresIn: '7d' });
    await cancelSecret(cancelled.controlToken);
    const afterCancel = await readControlStatus(cancelled.controlToken);
    expect(afterCancel?.state).toBe('cancelled');
    expect(afterCancel?.closedAt).toBeInstanceOf(Date);
    expect(afterCancel?.createdAt).toBeNull();
    // Closing never precedes the expiry the row was created with.
    expect(afterCancel?.closedAt!.getTime()).toBeLessThanOrEqual(afterCancel!.expiresAt!.getTime());
  });

  it('returns null for an unknown, malformed or purged control token', async () => {
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('purged')).payload, expiresIn: '7d' });
    await revealSecret(created.token, TEST_AUTH_KEY);

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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, passwordProtected: true, expiresIn: '7d' });

    const status = await readControlStatus(created.controlToken);
    // Enumerated rather than asserted field by field: a control link may report
    // instants and a state, and nothing else. The ciphertext, the payload and
    // the share token must never appear here.
    expect(Object.keys(status ?? {}).sort()).toEqual(['closedAt', 'createdAt', 'expiresAt', 'state']);
    expect(JSON.stringify(status)).not.toContain(payload);
  });
});

describe('cancelSecret', () => {
  it('deletes a pending secret, writes a cancelled receipt and blocks the reveal', async () => {
    const { payload } = await sealedSecret('cancel target');
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, passwordProtected: true, expiresIn: '7d' });

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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });

    expect(await cancelSecret('x'.repeat(43))).toEqual({ ok: false, reason: 'unavailable' });
    expect(await cancelSecret('not-a-token')).toEqual({ ok: false, reason: 'unavailable' });
    expect(await cancelSecret('')).toEqual({ ok: false, reason: 'unavailable' });

    expect(await countSecrets()).toBe(1);
    expect(await countReceipts()).toBe(0);
    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
  });

  it('refuses an already expired secret and leaves it to the cleanup job', async () => {
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('late cancel')).payload, expiresIn: '7d' });
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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
    await revealSecret(created.token, TEST_AUTH_KEY);

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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('twice')).payload, expiresIn: '7d' });
    await cancelSecret(created.controlToken);
    const second = await cancelSecret(created.controlToken);

    expect(second.ok).toBe(true);
    if (!second.ok) throw new Error('cancel did not return a status');
    expect(second.status.state).toBe('cancelled');
    expect(await countReceipts()).toBe(1);
  });

  it('never asks for a password, so it cannot be locked out by one', async () => {
    const created = await createSecret({
      authHash: TEST_AUTH_HASH,
      payload: (await sealedSecret('locked control')).payload,
      expiresIn: '7d',
      passwordProtected: true,
    });

    // The control link is not a credential: holding it is what authorises the
    // cancel, so no password is read, hashed or compared anywhere in the path.
    const result = await cancelSecret(created.controlToken);
    if (!result.ok) expect.unreachable('the control token was just created');
    // A cancelled secret is reported from its receipt, so the creation instant is
    // gone with the row and only the closing instant remains.
    expect(result.status).toEqual({
      state: 'cancelled',
      expiresAt: created.expiresAt,
      createdAt: null,
      closedAt: expect.any(Date),
    });
  });
});

describe('purgeExpired', () => {
  it('removes expired secrets, writes expired receipts and drops idle counters only', async () => {
    const expired = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('expired')).payload, expiresIn: '1d' });
    const live = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('live')).payload, expiresIn: '30d' });
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

    const revealed = await revealSecret(live.token, TEST_AUTH_KEY);
    expect(revealed.ok).toBe(true);
  });

  it('drops spent receipts only once their retention has passed', async () => {
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('spent')).payload, expiresIn: '7d' });
    await revealSecret(created.token, TEST_AUTH_KEY);

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
    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload: (await sealedSecret('both')).payload, expiresIn: '7d' });
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
