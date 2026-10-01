/**
 * Secret lifecycle: fidelity of the stored content, single use, passwords,
 * expiry and the peek endpoint that must never consume.
 */
import { beforeEach, describe, expect, it } from 'vitest';
import { createSecret, peekSecretPresence, purgeExpired, revealSecret } from '../src/lib/secrets.ts';
import {
  countRateLimits,
  countSecrets,
  fetchSecretRow,
  fetchRateLimitRows,
  forceExpire,
  insertRateLimitRow,
  resetEnv,
  setExpiresInSeconds,
  tableExists,
  utf8,
} from './helpers.ts';

beforeEach(async () => {
  await resetEnv();
});

describe('create and reveal without a password', () => {
  const payloads: ReadonlyArray<readonly [string, string]> = [
    ['plain ascii', 'the quick brown fox jumps over the lazy dog'],
    ['trailing spaces', 'secret with trailing spaces    '],
    ['trailing newline', 'ends with a newline\n'],
    ['trailing CRLF', 'windows line ending\r\n'],
    ['tabs and blank lines', '\tone\n\n\t\ttwo\r\n\r\n'],
    ['leading whitespace', '   indented'],
    ['single space', ' '],
    ['leading BOM', '\uFEFFpayload preceded by a byte order mark'],
    ['emoji and astral pairs', '😀🎉👩‍💻🇮🇹'],
    ['combining marks', 'e\u0301 vs \u00E9'],
    ['right to left text', 'مرحبا بالعالم'],
    ['json looking text', '{"secret":"value","nested":{"a":[1,2,3]}}'],
    ['sql looking text', "'); DROP TABLE secrets; --"],
  ];

  it.each(payloads)('round-trips %s byte for byte and is then unavailable', async (_label, plaintext) => {
    const created = await createSecret({ secret: plaintext, expiresInDays: 7 });

    const first = await revealSecret(created.token);
    expect(first.ok).toBe(true);
    if (!first.ok) throw new Error('secret was not revealed');
    expect(first.secret).toBe(plaintext);
    expect(utf8(first.secret).equals(utf8(plaintext))).toBe(true);

    const second = await revealSecret(created.token);
    expect(second).toEqual({ ok: false, reason: 'unavailable' });
    expect(await countSecrets()).toBe(0);
  });

  it('returns a well formed token and an expiry derived from the database clock', async () => {
    const before = Date.now();
    const created = await createSecret({ secret: 'expiry check', expiresInDays: 1 });
    const delta = created.expiresAt.getTime() - before;
    const day = 24 * 60 * 60 * 1000;
    expect(created.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(delta).toBeGreaterThan(day - 10_000);
    expect(delta).toBeLessThan(day + 10_000);
  });

  it('ignores a password supplied at reveal time for an unprotected secret', async () => {
    const created = await createSecret({ secret: 'no password needed', expiresInDays: 7 });
    expect(await revealSecret(created.token, 'an unexpected password')).toEqual({
      ok: true,
      secret: 'no password needed',
    });
  });
});

describe('create and reveal with a password', () => {
  const PASSWORD = 'correct horse battery staple';

  it('reveals with the correct password and is unavailable afterwards', async () => {
    const created = await createSecret({
      secret: 'protected payload',
      expiresInDays: 7,
      password: PASSWORD,
    });
    expect(await revealSecret(created.token, PASSWORD)).toEqual({
      ok: true,
      secret: 'protected payload',
    });
    expect(await revealSecret(created.token, PASSWORD)).toEqual({ ok: false, reason: 'unavailable' });
  });

  it('does not consume the secret when the password is wrong', async () => {
    const created = await createSecret({
      secret: 'still readable',
      expiresInDays: 7,
      password: PASSWORD,
    });

    for (const attempt of ['wrong', PASSWORD.toUpperCase(), `${PASSWORD} `, 'w']) {
      expect(await revealSecret(created.token, attempt)).toEqual({
        ok: false,
        reason: 'bad_password',
      });
    }
    expect(await countSecrets()).toBe(1);

    expect(await revealSecret(created.token, PASSWORD)).toEqual({
      ok: true,
      secret: 'still readable',
    });
  });

  it('reports bad_password when the password is missing entirely', async () => {
    const created = await createSecret({ secret: 'needs a password', expiresInDays: 7, password: PASSWORD });
    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'bad_password' });
    expect(await revealSecret(created.token, '')).toEqual({ ok: false, reason: 'bad_password' });
    expect(await countSecrets()).toBe(1);
  });

  it('keeps protected content byte exact', async () => {
    const payload = 'line1\r\nline2\t\ttrailing   \n\uFEFF😀';
    const created = await createSecret({ secret: payload, expiresInDays: 7, password: PASSWORD });
    const result = await revealSecret(created.token, PASSWORD);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('secret was not revealed');
    expect(utf8(result.secret).equals(utf8(payload))).toBe(true);
  });
});

describe('peekSecretPresence', () => {
  it('reports whether a password is required without consuming the secret', async () => {
    const open = await createSecret({ secret: 'open secret', expiresInDays: 7 });
    const locked = await createSecret({ secret: 'locked secret', expiresInDays: 7, password: 'pw' });

    expect(await peekSecretPresence(open.token)).toEqual({ requiresPassword: false });
    expect(await peekSecretPresence(locked.token)).toEqual({ requiresPassword: true });
    expect(await countSecrets()).toBe(2);
  });

  it('returns null for unknown, expired and malformed tokens', async () => {
    const expired = await createSecret({ secret: 'gone', expiresInDays: 7 });
    await forceExpire(expired.token);

    expect(await peekSecretPresence('x'.repeat(43))).toBeNull();
    expect(await peekSecretPresence(expired.token)).toBeNull();
    expect(await peekSecretPresence('not-a-token')).toBeNull();
    expect(await peekSecretPresence('')).toBeNull();
  });

  it('never consumes the row, however often it is called', async () => {
    const created = await createSecret({ secret: 'peek only', expiresInDays: 7 });

    for (let attempt = 0; attempt < 25; attempt += 1) {
      expect(await peekSecretPresence(created.token)).toEqual({ requiresPassword: false });
    }

    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
    expect(await revealSecret(created.token)).toEqual({ ok: true, secret: 'peek only' });
    expect(await countSecrets()).toBe(0);
  });
});

describe('expiration', () => {
  it('reports unavailable once expires_at is in the past and leaves the row for the cleanup job', async () => {
    const created = await createSecret({ secret: 'expiring payload', expiresInDays: 1 });
    await forceExpire(created.token);

    expect(await revealSecret(created.token)).toEqual({ ok: false, reason: 'unavailable' });
    // The conditional delete must not remove an already expired row.
    expect(await countSecrets()).toBe(1);
    expect(await fetchSecretRow(created.token)).toBeDefined();
  });

  it('still reveals a secret whose expires_at is one hour ahead', async () => {
    const created = await createSecret({ secret: 'not yet expired', expiresInDays: 1 });
    await setExpiresInSeconds(created.token, 3600);

    expect(await revealSecret(created.token)).toEqual({ ok: true, secret: 'not yet expired' });
    expect(await countSecrets()).toBe(0);
  });

  it('never reveals a protected secret that expired, even with the right password', async () => {
    const created = await createSecret({
      secret: 'expired and locked',
      expiresInDays: 1,
      password: 'pw',
    });
    await setExpiresInSeconds(created.token, -1);

    expect(await revealSecret(created.token, 'pw')).toEqual({ ok: false, reason: 'unavailable' });
  });
});

describe('XSS and injection payloads', () => {
  const hostile: ReadonlyArray<readonly [string, string]> = [
    ['script tag', '<script>alert(1)</script>'],
    ['image error handler', '<img src=x onerror=alert(1)>'],
    ['statement terminator', '"; DROP TABLE secrets; --'],
  ];

  it.each(hostile)('returns a %s payload verbatim', async (_label, payload) => {
    const created = await createSecret({ secret: payload, expiresInDays: 7 });
    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('secret was not revealed');
    expect(result.secret).toBe(payload);
    expect(utf8(result.secret).equals(utf8(payload))).toBe(true);
  });

  it('leaves the schema intact after hostile payloads', async () => {
    expect(await tableExists('secrets')).toBe(true);
    expect(await tableExists('rate_limits')).toBe(true);
    const created = await createSecret({ secret: "'; DELETE FROM secrets; --", expiresInDays: 7 });
    expect(await revealSecret(created.token)).toEqual({ ok: true, secret: "'; DELETE FROM secrets; --" });
    expect(await countSecrets()).toBe(0);
    expect(await tableExists('secrets')).toBe(true);
  });
});

describe('purgeExpired', () => {
  it('removes expired secrets, keeps live ones and drops idle counters only', async () => {
    const expired = await createSecret({ secret: 'expired', expiresInDays: 1 });
    const live = await createSecret({ secret: 'live', expiresInDays: 30 });
    await forceExpire(expired.token);
    await insertRateLimitRow('create', 'stale-subject', 7200, 9);
    await insertRateLimitRow('reveal', 'fresh-subject', 5, 3);

    const result = await purgeExpired(3600);
    expect(result).toEqual({ secrets: 1, counters: 1 });

    expect(await fetchSecretRow(expired.token)).toBeUndefined();
    expect(await fetchSecretRow(live.token)).toBeDefined();
    expect(await fetchRateLimitRows('create', 'stale-subject')).toHaveLength(0);
    expect(await fetchRateLimitRows('reveal', 'fresh-subject')).toHaveLength(1);
    expect(await countRateLimits()).toBe(1);

    expect(await revealSecret(live.token)).toEqual({ ok: true, secret: 'live' });
  });

  it('reports zeroes when there is nothing to remove', async () => {
    expect(await purgeExpired(3600)).toEqual({ secrets: 0, counters: 0 });
  });
});
