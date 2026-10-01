/**
 * Storage invariants and token handling.
 *
 * Everything here inspects the `secrets` table directly: the point is to prove
 * that what the application persists is only what it is allowed to persist, and
 * that malformed tokens and corrupted password hashes can never turn into a
 * readable secret. No assertion message contains secret content.
 */
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import {
  SCRYPT_PARAMS,
  decryptSecret,
  hashPassword,
  hashToken,
  isValidTokenShape,
  verifyPassword,
} from '../src/lib/crypto.ts';
import { query } from '../src/lib/db.ts';
import { getConfig } from '../src/lib/env.ts';
import { createSecret, purgeExpired, readControlStatus, revealSecret } from '../src/lib/secrets.ts';
import {
  countReceipts,
  countSecrets,
  fetchReceipt,
  fetchReceiptJson,
  fetchSecretRow,
  forceExpire,
  resetEnv,
  secretRowJson,
  sealedSecret,
} from './helpers.ts';

const PROBE_TEXT = 'STORAGE-PROBE-4f7c1e9a:correct horse battery staple';
const PROBE_PASSWORD = 'PW-PROBE-9d2b6f0a';
const HOUR_SECONDS = 3600;
const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

beforeEach(async () => {
  await resetEnv();
});

/**
 * The opaque payload a browser would have produced for PROBE_TEXT.
 *
 * The server never sees the text, so every test here is about what it actually
 * persists: the sealed payload, its hash and the password hash. Cached so the
 * probe is the same value in every test, which keeps the "same plaintext twice"
 * assertions about the storage layer rather than about the content key.
 */
let probeCache: string | undefined;
async function probe(): Promise<string> {
  probeCache ??= (await sealedSecret(PROBE_TEXT)).payload;
  return probeCache;
}

/** Boolean containment, so a failure message never echoes the probe value. */
function contains(haystack: string, needle: string): boolean {
  return haystack.includes(needle);
}

/** Every textual encoding of a fragment that could plausibly survive. */
function encodings(value: string): string[] {
  const bytes = Buffer.from(value, 'utf8');
  const base64 = bytes.toString('base64');
  const base64url = bytes.toString('base64url');
  const hex = bytes.toString('hex');
  return [
    value,
    base64,
    base64url,
    hex,
    base64.slice(0, 24),
    base64.slice(-24),
    base64url.slice(0, 24),
    base64url.slice(-24),
    hex.slice(0, 24),
    hex.slice(-24),
  ];
}

describe('ciphertext', () => {
  it('stores no plaintext and no recognisable encoding of it', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);

    expect(row).toBeDefined();
    if (!row) throw new Error('secret row missing');
    for (const fragment of encodings(PROBE_TEXT)) {
      expect(contains(row.ciphertext, fragment)).toBe(false);
    }
    expect(contains(await secretRowJson(created.token), PROBE_TEXT)).toBe(false);
  });

  it('is a base64url sealed payload of nonce + ciphertext + tag', async () => {
    const payload = await probe();
    const created = await createSecret({ payload, expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    expect(row.ciphertext).toMatch(/^[A-Za-z0-9_-]+$/);
    const raw = Buffer.from(row.ciphertext, 'base64url');
    // 12 byte nonce + payload + 16 byte auth tag for the outer, deployment keyed
    // envelope. The browser's own envelope is inside the payload and is not
    // readable here: the key for that one never left the browser.
    expect(raw.byteLength).toBe(12 + Buffer.byteLength(payload, 'utf8') + 16);
    // Canonical unpadded base64url: the stored text is exactly the encoding.
    expect(raw.toString('base64url')).toBe(row.ciphertext);
    expect(row.ciphertext).toHaveLength(
      4 * Math.floor(raw.byteLength / 3) + (raw.byteLength % 3 === 0 ? 0 : raw.byteLength % 3 + 1),
    );
    // Opening the outer layer yields the opaque payload the browser sent, and not
    // the text behind it.
    expect(decryptSecret(row.ciphertext, getConfig().encryptionKey)).toBe(payload);
    expect(payload).not.toBe(PROBE_TEXT);
  });

  it('uses a fresh nonce, so the same plaintext never produces the same row twice', async () => {
    const first = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const second = await createSecret({ payload: await probe(), expiresIn: '7d' });

    const firstRow = await fetchSecretRow(first.token);
    const secondRow = await fetchSecretRow(second.token);
    if (!firstRow || !secondRow) throw new Error('secret row missing');

    expect(firstRow.ciphertext).not.toBe(secondRow.ciphertext);
    expect(firstRow.token_hash).not.toBe(secondRow.token_hash);
    expect(firstRow.control_hash).not.toBe(secondRow.control_hash);
    expect(await countSecrets()).toBe(2);
  });
});

describe('control token persistence', () => {
  it('stores the same sha256 hex for the control token, and never the token', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    const expected = createHash('sha256').update(created.controlToken, 'utf8').digest('hex');
    expect(row.control_hash).toBe(expected);
    expect(row.control_hash).toMatch(/^[0-9a-f]{64}$/);
    // The two tokens are hashed the same way but are not the same value.
    expect(row.control_hash).not.toBe(row.token_hash);
  });

  it('never stores the control token itself, anywhere in the row', async () => {
    const created = await createSecret({
      payload: await probe(),
      expiresIn: '7d',
      password: PROBE_PASSWORD,
    });
    const json = await secretRowJson(created.token);
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    expect(contains(json, created.controlToken)).toBe(false);
    expect(contains(row.ciphertext, created.controlToken)).toBe(false);
    expect(contains(row.password_hash ?? '', created.controlToken)).toBe(false);
    expect(json).toContain(row.control_hash);
  });

  it('resolves a control link through the hash, never through the secret token', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    // A share token must not open a control link, even a well formed one.
    expect(await readControlStatus(created.token)).toBeNull();
    expect((await readControlStatus(created.controlToken))?.state).toBe('pending');
  });
});

describe('receipt persistence', () => {
  it('stores only a state, a hash and two timestamps, never content', async () => {
    const payload = await probe();
    const created = await createSecret({ payload, expiresIn: '1d', password: PROBE_PASSWORD });
    await forceExpire(created.token);
    await purgeExpired(HOUR_SECONDS);

    const receipt = await fetchReceipt(created.controlToken);
    if (!receipt) throw new Error('receipt missing');
    expect(receipt.state).toBe('expired');
    expect(receipt.control_hash).toMatch(/^[0-9a-f]{64}$/);

    const json = await fetchReceiptJson(created.controlToken);
    expect(json).not.toContain(payload);
    expect(json).not.toContain(PROBE_TEXT);
    expect(json).not.toContain(PROBE_PASSWORD);
    expect(json).not.toContain(created.token);
    expect(json).not.toContain(created.controlToken);
  });

  it('keys the receipt on the control hash, not on the secret token hash', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '1d' });
    await revealSecret(created.token);

    const receipt = await fetchReceipt(created.controlToken);
    if (!receipt) throw new Error('receipt missing');
    expect(receipt.control_hash).not.toBe(hashToken(created.token));
    expect(await countReceipts()).toBe(1);
  });
});

describe('token persistence', () => {
  it('stores the lowercase 64 character sha256 hex of the token', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    const expected = createHash('sha256').update(created.token, 'utf8').digest('hex');
    expect(row.token_hash).toBe(expected);
    expect(row.token_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.token_hash).toBe(hashToken(created.token));
    // The hash is not reversible to the token.
    expect(contains(row.token_hash, created.token)).toBe(false);
  });

  it('never stores the token itself, anywhere in the row', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');
    const json = await secretRowJson(created.token);

    expect(contains(json, created.token)).toBe(false);
    expect(contains(row.ciphertext, created.token)).toBe(false);
    expect(contains(row.password_hash ?? '', created.token)).toBe(false);
    expect(contains(row.created_at.toISOString(), created.token)).toBe(false);
    expect(json).toContain(row.token_hash);
  });
});

describe('password persistence', () => {
  it('stores a salted scrypt hash with explicit parameters and no plaintext', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');
    if (!row.password_hash) throw new Error('password_hash is null');

    const stored = row.password_hash;
    expect(stored.startsWith('scrypt$')).toBe(true);
    const parts = stored.split('$');
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe('scrypt');
    expect(Number(parts[1])).toBe(SCRYPT_PARAMS.N);
    expect(Number(parts[2])).toBe(SCRYPT_PARAMS.r);
    expect(Number(parts[3])).toBe(SCRYPT_PARAMS.p);
    expect(Buffer.from(parts[4] ?? '', 'base64url')).toHaveLength(16);
    expect(Buffer.from(parts[5] ?? '', 'base64url')).toHaveLength(SCRYPT_PARAMS.keyLength);
    expect(contains(stored, PROBE_PASSWORD)).toBe(false);
    expect(contains(await secretRowJson(created.token), PROBE_PASSWORD)).toBe(false);
  });

  it('salts every hash, so two secrets with the same password store different values', async () => {
    const first = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });
    const second = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });

    const firstRow = await fetchSecretRow(first.token);
    const secondRow = await fetchSecretRow(second.token);
    expect(firstRow?.password_hash).toBeTruthy();
    expect(firstRow?.password_hash).not.toBe(secondRow?.password_hash);
  });

  it('stores NULL, not an empty string, when no password is set', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    expect(row?.password_hash).toBeNull();
  });
});

describe('expiry storage', () => {
  async function expiryDrift(
    token: string,
    days: number,
  ): Promise<{ fromCreatedAt: number; fromDatabaseNow: number }> {
    const { rows } = await query<{ from_created: number; from_now: number }>(
      `SELECT
         EXTRACT(EPOCH FROM (expires_at - (created_at + make_interval(days => $2::int))))::float8 AS from_created,
         EXTRACT(EPOCH FROM (expires_at - (now() + make_interval(days => $2::int))))::float8 AS from_now
         FROM secrets
        WHERE token_hash = $1`,
      [hashToken(token), days],
    );
    const row = rows[0];
    if (!row) throw new Error('secret row missing');
    return { fromCreatedAt: row.from_created, fromDatabaseNow: row.from_now };
  }

  it.each([1, 7, 30])('derives expires_at from the database clock for %i days', async (days) => {
    const created = await createSecret({ payload: await probe(), expiresIn: days === 1 ? '1d' : days === 7 ? '7d' : '30d' });
    const drift = await expiryDrift(created.token, days);

    // created_at is written by the database default, so an expiry that sits
    // exactly `days` after it can only have been computed by the same clock.
    // A timestamp computed in the application would drift with the app host.
    expect(Math.abs(drift.fromCreatedAt)).toBeLessThan(2);
    expect(Math.abs(drift.fromDatabaseNow)).toBeLessThan(5);
  });

  it('returns to the caller the very timestamp the database stored', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    const row = await fetchSecretRow(created.token);
    if (!row) throw new Error('secret row missing');

    expect(created.expiresAt.getTime()).toBe(row.expires_at.getTime());
    expect(Math.abs(created.expiresAt.getTime() - (Date.now() + 7 * DAY))).toBeLessThan(10_000);
  });

  it('keeps the row unreadable once the stored expiry is in the past', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '1d', password: PROBE_PASSWORD });
    await query(`UPDATE secrets SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, [
      hashToken(created.token),
    ]);

    expect(await revealSecret(created.token, PROBE_PASSWORD)).toEqual({ ok: false, reason: 'unavailable' });
  });
});

describe('token shape', () => {
  it('accepts a generated token', async () => {
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    expect(isValidTokenShape(created.token)).toBe(true);
  });

  it('accepts any 43 character base64url string, existing secret or not', async () => {
    // The check is about the encoding of 32 random bytes, not about existence:
    // a well formed token with no row is rejected by the lookup, not here.
    const created = await createSecret({ payload: await probe(), expiresIn: '7d' });
    expect(isValidTokenShape(created.token)).toBe(true);
    expect(isValidTokenShape('x'.repeat(43))).toBe(true);
    expect(isValidTokenShape('-_-'.repeat(14) + '-')).toBe(true);
    expect(isValidTokenShape('x'.repeat(42) + '9')).toBe(true);
  });

  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['empty', ''],
    ['blank', ' '],
    ['too short', 'x'.repeat(42)],
    ['too long', 'x'.repeat(44)],
    ['with a plus', `${'x'.repeat(42)}+`],
    ['with a slash', `${'x'.repeat(42)}/`],
    ['with padding', `${'x'.repeat(42)}=`],
    ['with a dot', `${'x'.repeat(42)}.`],
    ['with a colon', `${'x'.repeat(42)}:`],
    ['with a percent', `${'x'.repeat(42)}%`],
    ['with a newline', `${'x'.repeat(42)}\n`],
    ['with an inner space', `${'x'.repeat(21)} ${'x'.repeat(21)}`],
    ['non ascii', 'é'.repeat(43)],
    ['non ascii suffix', `${'x'.repeat(42)}€`],
    ['a sentence', 'this-is-not-a-token-but-looks-quite-like-one!!'],
  ];

  it.each(malformed)('rejects a %s token', (_label, token) => {
    expect(isValidTokenShape(token)).toBe(false);
  });
});

describe('revealSecret with a malformed token', () => {
  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['empty', ''],
    ['well formed but unused', 'x'.repeat(43)],
    ['with a plus', `${'x'.repeat(42)}+`],
    ['with a slash', `${'x'.repeat(42)}/`],
    ['with a percent', `${'x'.repeat(42)}%`],
    ['non ascii', 'é'.repeat(43)],
    ['a sentence', "'; DROP TABLE secrets; --"],
  ];

  it.each(malformed)('returns unavailable for a %s token and changes nothing', async (_label, token) => {
    const live = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });
    const before = await secretRowJson(live.token);

    expect(await revealSecret(token)).toEqual({ ok: false, reason: 'unavailable' });
    expect(await revealSecret(token, PROBE_PASSWORD)).toEqual({ ok: false, reason: 'unavailable' });
    // The malformed attempt must not consume, delete or alter anything.
    expect(await countSecrets()).toBe(1);
    expect(await secretRowJson(live.token)).toBe(before);
    expect(await revealSecret(live.token, PROBE_PASSWORD)).toEqual({ ok: true, payload: await probe() });
  });

  it('treats a protected secret as unavailable, not as bad_password, for a malformed token', async () => {
    const live = await createSecret({ payload: await probe(), expiresIn: '7d', password: PROBE_PASSWORD });
    // An unknown token must not be distinguishable from a wrong password: the
    // answer reveals nothing about whether a protected secret exists.
    expect(await revealSecret('x'.repeat(43), 'wrong-password')).toEqual({
      ok: false,
      reason: 'unavailable',
    });
    expect(await revealSecret('x'.repeat(43), PROBE_PASSWORD)).toEqual({
      ok: false,
      reason: 'unavailable',
    });
    expect(await countSecrets()).toBe(1);
    expect(await revealSecret(live.token, PROBE_PASSWORD)).toEqual({ ok: true, payload: await probe() });
  });
});

describe('verifyPassword against corrupted stored values', () => {
  // A value that is not a well formed scrypt hash must fail closed: the callers
  // turn a false into "wrong password" and into a 403, so a throw or, worse, a
  // true would be a security defect.
  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['empty string', ''],
    ['scheme only', 'scrypt'],
    ['scheme and separator only', 'scrypt$'],
    ['one dollar short', 'scrypt$1024$8$1$c2FsdA'],
    ['one field too many', 'scrypt$1024$8$1$c2FsdA$aGFzaA$extra'],
    ['non numeric parameters', 'scrypt$a$b$c$d$e'],
    ['a different algorithm', 'bcrypt$1$2$3$4$5'],
    ['a different algorithm with a real body', 'pbkdf2$32768$8$1$c2FsdA$aGFzaA'],
    ['an empty salt', 'scrypt$1024$8$1$$aGFzaA'],
    ['an empty hash body', 'scrypt$1024$8$1$c2FsdA$'],
    ['an invalid base64 hash body', 'scrypt$1024$8$1$c2FsdA$!!!not-base64!!!'],
    // Known defect in src/lib/crypto.ts: a body that decodes to zero bytes asks
    // scrypt for a zero length key, and timingSafeEqual reports two empty
    // buffers as equal, so any password is accepted.
    ['a hash body that decodes to nothing', 'scrypt$1024$8$1$c2FsdA$%'],
    ['a salt and hash body that decode to nothing', 'scrypt$1024$8$1$%$%'],
    ['a zero cost factor', 'scrypt$0$8$1$c2FsdA$aGFzaA'],
    ['a cost factor of one', 'scrypt$1$8$1$c2FsdA$aGFzaA'],
    ['a negative cost factor', 'scrypt$-1024$8$1$c2FsdA$aGFzaA'],
    ['a cost factor beyond memory', 'scrypt$1073741824$8$1$c2FsdA$aGFzaA'],
    ['a huge cost factor as text', 'scrypt$99999999999999999999$8$1$c2FsdA$aGFzaA'],
    ['a fractional cost factor', 'scrypt$1024.5$8$1$c2FsdA$aGFzaA'],
    ['whitespace parameters', 'scrypt$ $ $ $ $ '],
    ['a truncated scrypt value', 'scrypt$32768$8$1'],
  ];

  it.each(malformed)('returns false instead of throwing for a %s', async (_label, stored) => {
    await expect(verifyPassword(PROBE_PASSWORD, stored)).resolves.toBe(false);
    await expect(verifyPassword('', stored)).resolves.toBe(false);
  });

  it('returns false when the stored hash body does not match the password length', async () => {
    // Truncate a real hash body: the derived key is recomputed at the shortened
    // length, so the comparison must fail rather than throw or succeed.
    const reference = await hashPassword(PROBE_PASSWORD);
    const parts = reference.split('$');
    const truncated = [...parts.slice(0, 5), Buffer.alloc(32, 0x62).toString('base64url')].join('$');
    expect(truncated).not.toBe(reference);

    await expect(verifyPassword(PROBE_PASSWORD, truncated)).resolves.toBe(false);
    await expect(verifyPassword(PROBE_PASSWORD, reference)).resolves.toBe(true);
  });

  it('rejects a real hash whose salt was replaced, without throwing', async () => {
    const reference = await hashPassword(PROBE_PASSWORD);
    const parts = reference.split('$');
    const tampered = ['scrypt', parts[1] ?? '', parts[2] ?? '', parts[3] ?? '', 'b3RoZXItc2FsdA', parts[5] ?? ''].join(
      '$',
    );

    await expect(verifyPassword(PROBE_PASSWORD, tampered)).resolves.toBe(false);
    await expect(verifyPassword(PROBE_PASSWORD, reference)).resolves.toBe(true);
  });

  it('normalizes NFKC exactly like the hashing side', async () => {
    const stored = await hashPassword('mot de passe e\u0301');

    await expect(verifyPassword('mot de passe \u00E9', stored)).resolves.toBe(true);
    await expect(verifyPassword('mot de passe e\u0301', stored)).resolves.toBe(true);
    // NFKC compatibility forms: U+FB01 LATIN SMALL LIGATURE FI folds to "fi".
    const ligature = await hashPassword('\uFB01le');
    await expect(verifyPassword('file', ligature)).resolves.toBe(true);
    await expect(verifyPassword('\uFB01le', ligature)).resolves.toBe(true);
  });
});
