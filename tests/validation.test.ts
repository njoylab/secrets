/**
 * Server side input limits: byte size of the secret, the expiry window and the
 * password length. Every rejection must be a typed validation error, never a
 * generic 500 from the API layer.
 */
import { Buffer } from 'node:buffer';
import { beforeEach, describe, expect, it } from 'vitest';
import { readJsonBody } from '../src/lib/api-guard.ts';
import {
  DEFAULT_EXPIRY_DAYS,
  MAX_CREATE_BODY_BYTES,
  MAX_EXPIRY_DAYS,
  MAX_PASSWORD_LENGTH,
  MAX_REVEAL_BODY_BYTES,
  MAX_SECRET_BYTES,
  MIN_EXPIRY_DAYS,
  createSecret,
  revealSecret,
} from '../src/lib/secrets.ts';
import { captureSecretError, fetchSecretRow, payloadOfBytes, resetEnv, utf8 } from './helpers.ts';

const DAY = 24 * 60 * 60 * 1000;

/** Worst case for JSON: a control character expands to a six byte escape. */
const ESCAPED_UNIT = '\u0001';

function jsonPost(body: unknown): Request {
  return new Request('https://secrets.example.com/api/secrets', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(async () => {
  await resetEnv();
});

describe('secret size', () => {
  it('rejects an empty secret with secretRequired', async () => {
    const error = await captureSecretError(createSecret({ secret: '', expiresInDays: 7 }));
    expect(error.code).toBe('secretRequired');
    expect(error.name).toBe('SecretValidationError');
  });

  it('rejects non string secrets, as forwarded by the untyped HTTP body', async () => {
    for (const secret of [undefined, null, 42, {}, ['a']]) {
      const error = await captureSecretError(
        createSecret({ secret: secret as unknown as string, expiresInDays: 7 }),
      );
      expect(error.code).toBe('secretRequired');
    }
  });

  it('accepts a secret of exactly 50 KiB in UTF-8 bytes', async () => {
    const payload = payloadOfBytes(MAX_SECRET_BYTES);
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_SECRET_BYTES);
    expect(MAX_SECRET_BYTES).toBe(50 * 1024);

    const created = await createSecret({ secret: payload, expiresInDays: 7 });
    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('secret was not revealed');
    expect(utf8(result.secret).equals(utf8(payload))).toBe(true);
  });

  it('rejects a multi byte payload one byte over the limit, even with fewer characters', async () => {
    const payload = payloadOfBytes(MAX_SECRET_BYTES + 1);
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_SECRET_BYTES + 1);
    // Characters alone would be below the limit, so this only fails on the byte count.
    expect(payload.length).toBeLessThan(MAX_SECRET_BYTES);

    const error = await captureSecretError(createSecret({ secret: payload, expiresInDays: 7 }));
    expect(error.code).toBe('secretTooLong');
  });

  it('rejects a plain ascii payload one byte over the limit', async () => {
    const payload = 'a'.repeat(MAX_SECRET_BYTES + 1);
    const error = await captureSecretError(createSecret({ secret: payload, expiresInDays: 7 }));
    expect(error.code).toBe('secretTooLong');
  });

  it('rejects a 4 byte emoji payload over the limit', async () => {
    const payload = '😀'.repeat(Math.floor(MAX_SECRET_BYTES / 4) + 1);
    expect(Buffer.byteLength(payload, 'utf8')).toBeGreaterThan(MAX_SECRET_BYTES);
    const error = await captureSecretError(createSecret({ secret: payload, expiresInDays: 7 }));
    expect(error.code).toBe('secretTooLong');
  });
});

describe('request body size', () => {
  it('accepts a body whose JSON escapes push it past the 64 KiB default', async () => {
    // Under 50 KiB of text, over 64 KiB once serialized: a legitimate secret
    // that the old default rejected with badRequest.
    const payload = ESCAPED_UNIT.repeat(MAX_SECRET_BYTES);
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_SECRET_BYTES);
    const request = jsonPost({ secret: payload, expiresInDays: 7 });
    expect(Buffer.byteLength(await request.clone().text(), 'utf8')).toBeGreaterThan(64 * 1024);

    const body = await readJsonBody(request, MAX_CREATE_BODY_BYTES);
    expect(body).not.toBeNull();
    expect(body?.secret).toBe(payload);

    // The same payload survives creation and reveal unchanged.
    const created = await createSecret({ secret: payload, expiresInDays: 7 });
    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('secret was not revealed');
    expect(utf8(result.secret).equals(utf8(payload))).toBe(true);
  });

  it('accepts quotes and backslashes, which expand two bytes each', async () => {
    const payload = '"\\'.repeat(Math.floor(MAX_SECRET_BYTES / 2));
    const body = await readJsonBody(jsonPost({ secret: payload, expiresInDays: 7 }), MAX_CREATE_BODY_BYTES);
    expect(body?.secret).toBe(payload);

    const created = await createSecret({ secret: payload, expiresInDays: 7 });
    const result = await revealSecret(created.token);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('secret was not revealed');
    expect(result.secret).toBe(payload);
  });

  it('rejects a body one byte over the creation ceiling, before reading it', async () => {
    const payload = ESCAPED_UNIT.repeat(MAX_SECRET_BYTES);
    const oversized = jsonPost({ secret: payload, expiresInDays: 7, padding: 'x'.repeat(MAX_CREATE_BODY_BYTES) });
    expect(Buffer.byteLength(await oversized.clone().text(), 'utf8')).toBeGreaterThan(MAX_CREATE_BODY_BYTES);
    expect(await readJsonBody(oversized, MAX_CREATE_BODY_BYTES)).toBeNull();
    // A declared Content-Length over the ceiling is refused without a read.
    const declared = new Request('https://secrets.example.com/api/secrets', {
      method: 'POST',
      headers: { 'content-length': String(MAX_CREATE_BODY_BYTES + 1) },
      body: JSON.stringify({ secret: payload }),
    });
    expect(await readJsonBody(declared, MAX_CREATE_BODY_BYTES)).toBeNull();
  });

  it('keeps the global default small, so other endpoints do not inherit the creation size', async () => {
    const payload = ESCAPED_UNIT.repeat(MAX_SECRET_BYTES);
    expect(await readJsonBody(jsonPost({ secret: payload, expiresInDays: 7 }))).toBeNull();
  });

  it('keeps a small ceiling on the reveal body', () => {
    // A reveal carries a 43 character token and a password, never the secret.
    expect(MAX_REVEAL_BODY_BYTES).toBeLessThan(MAX_CREATE_BODY_BYTES);
    expect(MAX_REVEAL_BODY_BYTES).toBe((43 + MAX_PASSWORD_LENGTH) * 6 + 256);
    expect(MAX_REVEAL_BODY_BYTES).toBeLessThan(8 * 1024);
  });

  it('still reports secretTooLong for a decoded secret over 50 KiB', async () => {
    // Fits in the creation ceiling, so it must fail validation, not parsing.
    const payload = ESCAPED_UNIT.repeat(MAX_SECRET_BYTES + 1);
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_SECRET_BYTES + 1);
    expect(Buffer.byteLength(JSON.stringify({ secret: payload }), 'utf8')).toBeLessThan(MAX_CREATE_BODY_BYTES);

    const body = await readJsonBody(jsonPost({ secret: payload, expiresInDays: 7 }), MAX_CREATE_BODY_BYTES);
    expect(body?.secret).toBe(payload);
    const error = await captureSecretError(
      createSecret({ secret: body?.secret as string, expiresInDays: 7 }),
    );
    expect(error.code).toBe('secretTooLong');
  });
});

describe('expiry window', () => {
  const invalid: ReadonlyArray<readonly [string, unknown]> = [
    ['zero', 0],
    ['above the maximum', 31],
    ['fractional', 1.5],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['negative', -1],
    ['non numeric string', 'abc'],
    ['numeric string zero', '0'],
    ['missing', undefined],
    ['null', null],
    ['boolean', true],
  ];

  it.each(invalid)('rejects an expiry of %s with invalidExpiry', async (_label, expiresInDays) => {
    const error = await captureSecretError(
      createSecret({ secret: 'payload', expiresInDays: expiresInDays as number }),
    );
    expect(error.code).toBe('invalidExpiry');
  });

  const accepted: ReadonlyArray<readonly [number, number]> = [
    [MIN_EXPIRY_DAYS, 1],
    [DEFAULT_EXPIRY_DAYS, 7],
    [MAX_EXPIRY_DAYS, 30],
  ];

  it.each(accepted)('accepts an expiry of %i days', async (days, _label) => {
    const before = Date.now();
    const created = await createSecret({ secret: 'payload', expiresInDays: days });
    const delta = created.expiresAt.getTime() - before;
    expect(delta).toBeGreaterThan(days * DAY - 10_000);
    expect(delta).toBeLessThan(days * DAY + 10_000);
  });

  it('exposes a default of 7 days for the form to submit', () => {
    expect(DEFAULT_EXPIRY_DAYS).toBe(7);
    expect(MIN_EXPIRY_DAYS).toBe(1);
    expect(MAX_EXPIRY_DAYS).toBe(30);
  });

  it('coerces a numeric string coming from a form field', async () => {
    const before = Date.now();
    const created = await createSecret({
      secret: 'payload',
      expiresInDays: '7' as unknown as number,
    });
    const delta = created.expiresAt.getTime() - before;
    expect(delta).toBeGreaterThan(7 * DAY - 10_000);
    expect(delta).toBeLessThan(7 * DAY + 10_000);
  });
});

describe('password length', () => {
  it('rejects a password longer than MAX_PASSWORD_LENGTH', async () => {
    const error = await captureSecretError(
      createSecret({
        secret: 'payload',
        expiresInDays: 7,
        password: 'p'.repeat(MAX_PASSWORD_LENGTH + 1),
      }),
    );
    expect(error.code).toBe('passwordTooLong');
  });

  it('accepts a password of exactly MAX_PASSWORD_LENGTH', async () => {
    const password = 'p'.repeat(MAX_PASSWORD_LENGTH);
    const created = await createSecret({ secret: 'payload', expiresInDays: 7, password });
    expect(await revealSecret(created.token, password)).toEqual({ ok: true, secret: 'payload' });
  });

  it('treats an empty password as no password at all', async () => {
    const created = await createSecret({ secret: 'payload', expiresInDays: 7, password: '' });
    const row = await fetchSecretRow(created.token);
    expect(row?.password_hash).toBeNull();
    expect(await revealSecret(created.token)).toEqual({ ok: true, secret: 'payload' });
  });

  it('normalises the password to NFKC before hashing', async () => {
    const decomposed = 'mot de passe e\u0301';
    const created = await createSecret({
      secret: 'payload',
      expiresInDays: 7,
      password: decomposed,
    });
    expect(await revealSecret(created.token, 'mot de passe \u00E9')).toEqual({
      ok: true,
      secret: 'payload',
    });
  });

  it('rejects a non string password', async () => {
    const error = await captureSecretError(
      createSecret({
        secret: 'payload',
        expiresInDays: 7,
        password: 1234 as unknown as string,
      }),
    );
    expect(error.code).toBe('passwordTooLong');
  });
});
