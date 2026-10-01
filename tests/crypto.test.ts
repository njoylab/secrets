/**
 * Unit tests for the cryptographic primitives. No database involved.
 */
import { Buffer } from 'node:buffer';
import { createHash, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  SCRYPT_PARAMS,
  decryptSecret,
  encryptSecret,
  generateToken,
  hashPassword,
  hashToken,
  isValidTokenShape,
  verifyPassword,
} from '../src/lib/crypto.ts';

const KEY = randomBytes(32);
const OTHER_KEY = randomBytes(32);

const TOKEN_SHAPE = /^[A-Za-z0-9_-]{43}$/;

describe('generateToken', () => {
  it('returns 43 base64url characters carrying 32 random bytes', () => {
    const token = generateToken();
    expect(token).toHaveLength(43);
    expect(token).toMatch(TOKEN_SHAPE);
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    expect(Buffer.from(token, 'base64url').toString('base64url')).toBe(token);
  });

  it('never repeats across 500 draws', () => {
    const seen = new Set<string>();
    for (let index = 0; index < 500; index += 1) seen.add(generateToken());
    expect(seen.size).toBe(500);
  });
});

describe('hashToken', () => {
  it('is the lowercase 64 character sha256 hex of the token', () => {
    const token = generateToken();
    const expected = createHash('sha256').update(token, 'utf8').digest('hex');
    expect(hashToken(token)).toBe(expected);
    expect(hashToken(token)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(token)).toBe(hashToken(token));
  });

  it('separates tokens that differ by one character', () => {
    const token = generateToken();
    const neighbour = `${token.slice(0, 42)}${token[42] === 'A' ? 'B' : 'A'}`;
    expect(hashToken(token)).not.toBe(hashToken(neighbour));
  });
});

describe('isValidTokenShape', () => {
  it('accepts a freshly generated token', () => {
    expect(isValidTokenShape(generateToken())).toBe(true);
  });

  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['empty', ''],
    ['blank', ' '],
    ['too short', 'x'.repeat(42)],
    ['too long', 'x'.repeat(44)],
    ['plus sign', `${'x'.repeat(42)}+`],
    ['slash', `${'x'.repeat(42)}/`],
    ['padding', `${'x'.repeat(42)}=`],
    ['dot', `${'x'.repeat(42)}.`],
    ['inner space', `${'x'.repeat(21)} ${'x'.repeat(21)}`],
    ['newline', `${'x'.repeat(42)}\n`],
    ['sentence', 'this-is-not-a-valid-token-shape'],
  ];

  it.each(malformed)('rejects a %s token', (_label, token) => {
    expect(isValidTokenShape(token)).toBe(false);
  });
});

describe('encryptSecret / decryptSecret', () => {
  const payloads: ReadonlyArray<readonly [string, string]> = [
    ['single character', 'a'],
    ['single space', ' '],
    ['empty-ish tab', '\t'],
    ['plain ascii', 'the quick brown fox jumps over the lazy dog'],
    ['leading and trailing spaces', '   padded   '],
    ['trailing newline', 'ends with a newline\n'],
    ['crlf line endings', 'first\r\nsecond\r\n'],
    ['tabs and blank lines', '\tone\n\n\ttwo\r\n\r\n'],
    ['leading BOM', '\uFEFFwith a byte order mark'],
    ['emoji and astral pairs', '😀🎉👩‍💻🇮🇹'],
    ['combining marks', 'e\u0301 vs \u00E9'],
    ['right to left text', 'مرحبا بالعالم'],
    ['json looking text', '{"secret":"value","nested":{"a":[1,2,3]}}'],
    ['sql looking text', "'); DROP TABLE secrets; --"],
    // NUL is excluded on purpose: it cannot be stored in a PostgreSQL text column.
    ['control characters', 'bell:\u0007 esc:\u001B'],
  ];

  it.each(payloads)('round-trips %s byte for byte', (_label, plaintext) => {
    const sealed = encryptSecret(plaintext, KEY);
    const opened = decryptSecret(sealed, KEY);
    expect(opened).toBe(plaintext);
    expect(Buffer.from(opened, 'utf8').equals(Buffer.from(plaintext, 'utf8'))).toBe(true);
  });

  it('round-trips a long unicode payload', () => {
    const plaintext = `${'\u00E9\u4F60\u597D😀'.repeat(20_000)}tail`;
    const opened = decryptSecret(encryptSecret(plaintext, KEY), KEY);
    expect(Buffer.from(opened, 'utf8').equals(Buffer.from(plaintext, 'utf8'))).toBe(true);
  });

  it('uses a fresh nonce, so the same plaintext seals differently every time', () => {
    const plaintext = 'identical plaintext';
    const first = encryptSecret(plaintext, KEY);
    const second = encryptSecret(plaintext, KEY);
    expect(first).not.toBe(second);
    expect(decryptSecret(first, KEY)).toBe(plaintext);
    expect(decryptSecret(second, KEY)).toBe(plaintext);
  });

  it('produces a base64url payload of nonce + ciphertext + tag', () => {
    const sealed = encryptSecret('abc', KEY);
    expect(sealed).toMatch(/^[A-Za-z0-9_-]+$/);
    // 12 byte nonce + 3 byte plaintext + 16 byte tag
    expect(Buffer.from(sealed, 'base64url')).toHaveLength(31);
  });

  it('cannot be decrypted with a different key', () => {
    const sealed = encryptSecret('top secret value', KEY);
    expect(() => decryptSecret(sealed, OTHER_KEY)).toThrow();
  });

  it('rejects a tampered ciphertext', () => {
    const raw = Buffer.from(encryptSecret('tamper evident payload', KEY), 'base64url');
    raw.writeUInt8((raw[14] ?? 0) ^ 0xff, 14);
    expect(() => decryptSecret(raw.toString('base64url'), KEY)).toThrow();
  });

  it('rejects a payload too short to contain a nonce and a tag', () => {
    expect(() => decryptSecret('', KEY)).toThrow('Ciphertext payload is too short');
    expect(() => decryptSecret(Buffer.from('short').toString('base64url'), KEY)).toThrow(
      'Ciphertext payload is too short',
    );
  });
});

describe('hashPassword', () => {
  it('stores scrypt parameters, a 16 byte salt and a 64 byte derived key', async () => {
    const stored = await hashPassword('correct horse battery staple');
    const parts = stored.split('$');
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe('scrypt');
    expect(Number(parts[1])).toBe(SCRYPT_PARAMS.N);
    expect(Number(parts[2])).toBe(SCRYPT_PARAMS.r);
    expect(Number(parts[3])).toBe(SCRYPT_PARAMS.p);
    expect(Buffer.from(parts[4] ?? '', 'base64url')).toHaveLength(16);
    expect(Buffer.from(parts[5] ?? '', 'base64url')).toHaveLength(SCRYPT_PARAMS.keyLength);
    expect(stored).not.toContain('correct horse');
  });

  it('salts each hash, so the same password never produces the same string', async () => {
    const [first, second] = await Promise.all([hashPassword('same password'), hashPassword('same password')]);
    expect(first).not.toBe(second);
    expect(await verifyPassword('same password', first)).toBe(true);
    expect(await verifyPassword('same password', second)).toBe(true);
  });
});

describe('verifyPassword', () => {
  it('accepts the correct password and rejects a wrong one', async () => {
    const stored = await hashPassword('the-right-password');
    expect(await verifyPassword('the-right-password', stored)).toBe(true);
    expect(await verifyPassword('the-wrong-password', stored)).toBe(false);
    expect(await verifyPassword('', stored)).toBe(false);
    expect(await verifyPassword('the-right-password ', stored)).toBe(false);
  });

  it('compares Unicode-equivalent passwords as equal', async () => {
    const stored = await hashPassword('e\u0301cole');
    expect(await verifyPassword('\u00E9cole', stored)).toBe(true);
  });

  const malformed: ReadonlyArray<readonly [string, string]> = [
    ['empty string', ''],
    ['scheme only', 'scrypt'],
    ['too few fields', 'scrypt$32768$8$1'],
    ['wrong scheme', 'pbkdf2$32768$8$1$c2FsdA$aGFzaA'],
    ['non numeric parameters', 'scrypt$a$b$c$d$e'],
    ['empty salt', 'scrypt$32768$8$1$$aGFzaA'],
    ['empty hash', 'scrypt$32768$8$1$c2FsdA$'],
    ['out of range cost', 'scrypt$999999999$8$1$QUFBQUFB$QUFBQUFB'],
  ];

  it.each(malformed)('returns false instead of throwing for a %s stored value', async (_label, stored) => {
    expect(await verifyPassword('anything', stored)).toBe(false);
  });
});
