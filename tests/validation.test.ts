/**
 * Server side input limits: byte size of the sealed payload, the expiry preset and
 * the password length. Every rejection must be a typed validation error, never a
 * generic 500 from the API layer.
 */
import { Buffer } from 'node:buffer';
import { beforeEach, describe, expect, it } from 'vitest';
import { readJsonBody } from '../src/lib/api-guard.ts';
import {
  DEFAULT_EXPIRY_PRESET,
  EXPIRY_PRESETS,
  EXPIRY_PRESET_SECONDS,
  MAX_CANCEL_BODY_BYTES,
  MAX_CREATE_BODY_BYTES,
  MAX_PAYLOAD_BYTES,
  MAX_REVEAL_BODY_BYTES,
  MAX_SECRET_BYTES,
  RECEIPT_RETENTION_DAYS,
  createSecret,
  revealSecret,
  type ExpiryPreset,
} from '../src/lib/secrets.ts';
import {
  captureSecretError,
  expectedStoredAuthHash,
  TEST_AUTH_HASH,
  TEST_AUTH_KEY,
  fetchSecretRow,
  payloadOfBytes,
  resetEnv,
  sealedSecret,
} from './helpers.ts';

function jsonPost(body: unknown, path = '/api/secrets'): Request {
  return new Request(`https://secrets.example.com${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

beforeEach(async () => {
  await resetEnv();
});

describe('payload size', () => {
  it('rejects an empty payload with payloadRequired', async () => {
    const error = await captureSecretError(createSecret({ authHash: TEST_AUTH_HASH, payload: '', expiresIn: '7d' }));
    expect(error.code).toBe('payloadRequired');
    expect(error.name).toBe('SecretValidationError');
  });

  it('rejects non string payloads, as forwarded by the untyped HTTP body', async () => {
    for (const payload of [undefined, null, 42, {}, ['a']]) {
      const error = await captureSecretError(
        createSecret({ authHash: TEST_AUTH_HASH, payload: payload as unknown as string, expiresIn: '7d' }),
      );
      expect(error.code).toBe('payloadRequired');
    }
  });

  it('accepts a sealed payload of exactly MAX_PAYLOAD_BYTES', async () => {
    const { payload } = await sealedSecret('a'.repeat(MAX_SECRET_BYTES));
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_PAYLOAD_BYTES);

    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
    const result = await revealSecret(created.token, TEST_AUTH_KEY);
    expect(result).toEqual({ ok: true, payload });
  });

  it('rejects a string that is not a sealed envelope', async () => {
    const error = await captureSecretError(createSecret({ authHash: TEST_AUTH_HASH, payload: 'payload', expiresIn: '7d' }));
    expect(error.code).toBe('invalidPayload');
  });

  it('rejects a payload one byte over the limit', async () => {
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES + 1);
    const error = await captureSecretError(createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' }));
    expect(error.code).toBe('payloadTooLong');
  });

  it('counts bytes, not characters, for a multi byte payload', async () => {
    // 3 byte characters: the character count is well under the limit, so this can
    // only fail on the byte count.
    const payload = payloadOfBytes(MAX_PAYLOAD_BYTES + 1);
    expect(Buffer.byteLength(payload, 'utf8')).toBe(MAX_PAYLOAD_BYTES + 1);
    expect(payload.length).toBeLessThan(MAX_PAYLOAD_BYTES);

    const error = await captureSecretError(createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' }));
    expect(error.code).toBe('payloadTooLong');
  });

  it('accepts a 50 KiB secret once the browser has sealed it', async () => {
    // The real ceiling on secret text is what the browser seals, not what the
    // server stores: a 50 KiB secret is 68,304 payload bytes and must pass.
    const { payload } = await sealedSecret('€'.repeat(Math.floor(MAX_SECRET_BYTES / 3)));
    expect(Buffer.byteLength(payload, 'utf8')).toBeLessThanOrEqual(MAX_PAYLOAD_BYTES);
    expect(payload.length).toBeLessThan(MAX_PAYLOAD_BYTES);

    const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' });
    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
  });

  it('rejects a sealed payload that could only come from an oversized secret', async () => {
    // One byte of ciphertext past the ceiling for a maximum size secret.
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES + 1);
    expect(payload.length).toBeGreaterThan(MAX_PAYLOAD_BYTES);
    const error = await captureSecretError(createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7d' }));
    expect(error.code).toBe('payloadTooLong');
  });

  it('documents the ceiling as the base64url length of the sealed envelope', () => {
    // 50 KiB of text plus a 12 byte nonce and a 16 byte tag, unpadded base64url.
    expect(MAX_SECRET_BYTES).toBe(50 * 1024);
    expect(MAX_PAYLOAD_BYTES).toBe(4 * Math.floor((50 * 1024 + 28) / 3));
  });
});

describe('request body size', () => {
  it('accepts a body whose JSON escapes push it past the 64 KiB default', async () => {
    // base64url and hex never expand, so use a maximum envelope and every field.
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES);
    const request = jsonPost({ payload, expiresIn: '30d', authHash: 'a'.repeat(64), passwordProtected: false });
    expect(Buffer.byteLength(await request.clone().text(), 'utf8')).toBeGreaterThan(64 * 1024);
    expect(Buffer.byteLength(await request.clone().text(), 'utf8')).toBeLessThanOrEqual(MAX_CREATE_BODY_BYTES);

    const body = await readJsonBody(request, MAX_CREATE_BODY_BYTES);
    expect(body).not.toBeNull();
    expect(body?.payload).toBe(payload);
    expect(body?.authHash).toBe('a'.repeat(64));
  });

  it('rejects a body one byte over the creation ceiling, before reading it', async () => {
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES);
    const oversized = jsonPost({
      payload,
      expiresIn: '7d',
      padding: 'x'.repeat(MAX_CREATE_BODY_BYTES),
    });
    expect(Buffer.byteLength(await oversized.clone().text(), 'utf8')).toBeGreaterThan(MAX_CREATE_BODY_BYTES);
    expect(await readJsonBody(oversized, MAX_CREATE_BODY_BYTES)).toBeNull();

    // A declared Content-Length over the ceiling is refused without a read.
    const declared = new Request('https://secrets.example.com/api/secrets', {
      method: 'POST',
      headers: { 'content-length': String(MAX_CREATE_BODY_BYTES + 1) },
      body: JSON.stringify({ payload }),
    });
    expect(await readJsonBody(declared, MAX_CREATE_BODY_BYTES)).toBeNull();
  });

  it('keeps the global default small, so other endpoints do not inherit the creation size', async () => {
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES);
    expect(await readJsonBody(jsonPost({ payload, expiresIn: '7d' }))).toBeNull();
  });

  it('keeps a small ceiling on the reveal body', () => {
    // A reveal carries a token and an auth key, never the payload.
    expect(MAX_REVEAL_BODY_BYTES).toBeLessThan(MAX_CREATE_BODY_BYTES);
    expect(MAX_REVEAL_BODY_BYTES).toBe(2 * 43 * 6 + 256);
    expect(MAX_REVEAL_BODY_BYTES).toBeLessThan(8 * 1024);
  });

  it('keeps the cancel body ceiling to a single token', () => {
    // A cancel carries one control token and nothing else.
    expect(MAX_CANCEL_BODY_BYTES).toBe(43 * 6 + 256);
    expect(MAX_CANCEL_BODY_BYTES).toBeLessThan(MAX_REVEAL_BODY_BYTES);
  });

  it('still reports payloadTooLong for a payload over the ceiling but inside the body', async () => {
    // Fits in the creation ceiling, so it must fail validation, not parsing.
    const payload = 'a'.repeat(MAX_PAYLOAD_BYTES + 1);
    expect(Buffer.byteLength(JSON.stringify({ payload }), 'utf8')).toBeLessThan(MAX_CREATE_BODY_BYTES);

    const body = await readJsonBody(jsonPost({ payload, expiresIn: '7d' }), MAX_CREATE_BODY_BYTES);
    expect(body?.payload).toBe(payload);
    const error = await captureSecretError(
      createSecret({ authHash: TEST_AUTH_HASH, payload: body?.payload as string, expiresIn: '7d' }),
    );
    expect(error.code).toBe('payloadTooLong');
  });
});

describe('expiry presets', () => {
  const invalid: ReadonlyArray<readonly [string, unknown]> = [
    ['a bare number', 7],
    ['zero', '0'],
    ['days without the unit', '7'],
    ['hours instead of days', '7h'],
    ['a preset with whitespace', ' 7d'],
    ['an unknown preset', '90d'],
    ['a non numeric string', 'abc'],
    ['missing', undefined],
    ['null', null],
    ['boolean', true],
  ];

  it.each(invalid)('rejects an expiry of %s with invalidExpiry', async (_label, expiresIn) => {
    const { payload } = await sealedSecret('expiry');
    const error = await captureSecretError(
      createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: expiresIn as ExpiryPreset }),
    );
    expect(error.code).toBe('invalidExpiry');
  });

  it('accepts exactly the four presets, and nothing else', async () => {
    expect(EXPIRY_PRESETS).toEqual(['1h', '1d', '7d', '30d']);
    for (const preset of EXPIRY_PRESETS) {
      const { payload } = await sealedSecret('preset');
      const created = await createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: preset });
      const delta = created.expiresAt.getTime() - Date.now();
      expect(delta).toBeGreaterThan(EXPIRY_PRESET_SECONDS[preset] * 1000 - 10_000);
      expect(delta).toBeLessThan(EXPIRY_PRESET_SECONDS[preset] * 1000 + 10_000);
    }
  });

  it('exposes a default of 7 days for the form to submit', () => {
    expect(DEFAULT_EXPIRY_PRESET).toBe('7d');
  });

  it('does not coerce a preset that merely looks like one', async () => {
    // The old API took days and accepted "7" as a string; a select cannot produce
    // that, and accepting it would make two spellings of the same request.
    const { payload } = await sealedSecret('coerce');
    const error = await captureSecretError(
      createSecret({ authHash: TEST_AUTH_HASH, payload, expiresIn: '7' as unknown as ExpiryPreset }),
    );
    expect(error.code).toBe('invalidExpiry');
  });

  it('keeps a receipt for a week after the secret closed', () => {
    expect(RECEIPT_RETENTION_DAYS).toBe(7);
  });
});

describe('auth hash', () => {
  it.each([
    ['missing', undefined],
    ['null', null],
    ['a number', 42],
    ['empty', ''],
    ['too short', 'a'.repeat(63)],
    ['too long', 'a'.repeat(65)],
    ['uppercase hex', 'A'.repeat(64)],
    ['not hex', 'g'.repeat(64)],
  ])('rejects an auth hash that is %s with invalidAuth', async (_label, authHash) => {
    const { payload } = await sealedSecret('auth hash shape');
    const error = await captureSecretError(createSecret({ payload, expiresIn: '7d', authHash: authHash as string }));
    expect(error.code).toBe('invalidAuth');
  });

  it.each([
    ['a string', 'true'],
    ['a number', 1],
    ['null', null],
  ])('rejects a password flag that is %s', async (_label, flag) => {
    const { payload } = await sealedSecret('password flag');
    const error = await captureSecretError(
      createSecret({ payload, expiresIn: '7d', authHash: TEST_AUTH_HASH, passwordProtected: flag as unknown as boolean }),
    );
    expect(error.code).toBe('invalidAuth');
  });

  it('stores the hash and the flag, and reveals only with the matching key', async () => {
    const { payload } = await sealedSecret('with auth');
    const created = await createSecret({ payload, expiresIn: '7d', authHash: TEST_AUTH_HASH, passwordProtected: true });
    const row = await fetchSecretRow(created.token);
    expect(row?.auth_hash).toBe(expectedStoredAuthHash(TEST_AUTH_HASH));
    expect(row?.has_password).toBe(true);
    expect(await revealSecret(created.token, TEST_AUTH_KEY)).toEqual({ ok: true, payload });
  });
});
