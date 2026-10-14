/**
 * Cryptographic primitives backed exclusively by `node:crypto`.
 *
 * Invariants:
 * - tokens carry 256 bits of randomness and are never stored, only hashed;
 * - secret content is sealed with AES-256-GCM under a random 96-bit nonce;
 * - stored auth hashes are keyed with an HMAC subkey derived from the deployment
 *   key, never with the AES key bytes themselves.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
} from 'node:crypto';
import { Buffer } from 'node:buffer';

export const TOKEN_BYTES = 32;

/** 32 random bytes encode to exactly 43 base64url characters. */
export const TOKEN_LENGTH = 43;

const NONCE_BYTES = 12;
const AUTH_TAG_BYTES = 16;
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

/** HKDF `info` label of the subkey that keys stored auth hashes. */
export const AUTH_HMAC_INFO = 'echovalue-secrets-v3:auth-hmac';

const AUTH_HMAC_KEY_BYTES = 32;

// Keyed by the Buffer instance, so a reloaded config (a new key Buffer) derives
// a fresh subkey and a dropped config releases its entry.
const authHmacKeys = new WeakMap<Buffer, Buffer>();

function authHmacKey(encryptionKey: Buffer): Buffer {
  let subkey = authHmacKeys.get(encryptionKey);
  if (!subkey) {
    subkey = Buffer.from(hkdfSync('sha256', encryptionKey, Buffer.alloc(0), AUTH_HMAC_INFO, AUTH_HMAC_KEY_BYTES));
    authHmacKeys.set(encryptionKey, subkey);
  }
  return subkey;
}

/**
 * Hex HMAC-SHA256 of a 32-byte auth hash under the deployment's auth subkey.
 * The result has the same 64-hex shape as the input, which the schema enforces.
 */
export function keyAuthHash(authHash: Buffer, encryptionKey: Buffer): string {
  return createHmac('sha256', authHmacKey(encryptionKey)).update(authHash).digest('hex');
}
