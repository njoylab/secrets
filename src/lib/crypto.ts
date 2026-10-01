/**
 * Cryptographic primitives backed exclusively by `node:crypto`.
 *
 * Invariants:
 * - tokens carry 256 bits of randomness and are never stored, only hashed;
 * - secret content is sealed with AES-256-GCM under a random 96-bit nonce;
 * - passwords use scrypt with explicit parameters and a random 16-byte salt.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual,
} from 'node:crypto';
import { Buffer } from 'node:buffer';

interface ScryptOptions {
  readonly N: number;
  readonly r: number;
  readonly p: number;
  readonly maxmem: number;
}

/** Promisified scrypt: expensive work happens here, never while a database lock is held. */
function scrypt(
  password: string,
  salt: Buffer,
  keyLength: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCallback(password, salt, keyLength, options, (error, derivedKey) => {
      if (error) reject(error);
      else resolve(derivedKey);
    });
  });
}

export const TOKEN_BYTES = 32;

/** 32 random bytes encode to exactly 43 base64url characters. */
export const TOKEN_LENGTH = 43;

const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const SALT_BYTES = 16;
const PASSWORD_HASH_BYTES = 64;

/** Explicit scrypt cost parameters, stored alongside every hash for future upgrades. */
export const SCRYPT_PARAMS = { N: 2 ** 15, r: 8, p: 1, keyLength: PASSWORD_HASH_BYTES } as const;

// scrypt needs roughly 128 * N * r bytes; the default 32 MiB budget is not enough for N = 2^15.
const SCRYPT_MAX_MEM = 192 * 1024 * 1024;

export function generateToken(): string {
  return randomBytes(TOKEN_BYTES).toString('base64url');
}

/** SHA-256 of the token, hex encoded. Deterministic lookup key, safe to index. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** 32 random bytes encode to exactly 43 base64url characters; reject anything else early. */
export function isValidTokenShape(token: string): boolean {
  return new RegExp(`^[A-Za-z0-9_-]{${TOKEN_LENGTH}}$`).test(token);
}

/** Seal plaintext as base64url(nonce || ciphertext || authTag). */
export function encryptSecret(plaintext: string, key: Buffer): string {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([nonce, ciphertext, authTag]).toString('base64url');
}

export function decryptSecret(payload: string, key: Buffer): string {
  const raw = Buffer.from(payload, 'base64url');
  if (raw.byteLength < NONCE_BYTES + AUTH_TAG_BYTES) {
    throw new Error('Ciphertext payload is too short');
  }
  const nonce = raw.subarray(0, NONCE_BYTES);
  const authTag = raw.subarray(raw.byteLength - AUTH_TAG_BYTES);
  const ciphertext = raw.subarray(NONCE_BYTES, raw.byteLength - AUTH_TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: AUTH_TAG_BYTES });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** Format: `scrypt$N$r$p$saltBase64url$hashBase64url`. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const derived = await scrypt(password.normalize('NFKC'), salt, SCRYPT_PARAMS.keyLength, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
    maxmem: SCRYPT_MAX_MEM,
  });
  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt.toString('base64url'),
    derived.toString('base64url'),
  ].join('$');
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

  const N = Number.parseInt(parts[1] ?? '', 10);
  const r = Number.parseInt(parts[2] ?? '', 10);
  const p = Number.parseInt(parts[3] ?? '', 10);
  const saltRaw = parts[4];
  const hashRaw = parts[5];
  if (!Number.isSafeInteger(N) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p)) return false;
  if (!saltRaw || !hashRaw) return false;

  let expected: Buffer;
  let actual: Buffer;
  try {
    expected = Buffer.from(hashRaw, 'base64url');
    const salt = Buffer.from(saltRaw, 'base64url');
    // A truncated or corrupted body decodes to a short buffer, and scrypt happily
    // returns a matching short key. Deriving with the caller's own length would
    // therefore make `timingSafeEqual` succeed for any password, so the stored
    // digest length is pinned to what `hashPassword` always writes.
    if (expected.byteLength !== SCRYPT_PARAMS.keyLength || salt.byteLength === 0) return false;

    actual = await scrypt(password.normalize('NFKC'), salt, expected.byteLength, {
      N,
      r,
      p,
      maxmem: SCRYPT_MAX_MEM,
    });
  } catch {
    return false;
  }
  if (actual.byteLength !== expected.byteLength) return false;
  return timingSafeEqual(actual, expected);
}