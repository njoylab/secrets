/**
 * Cryptographic primitives backed exclusively by `node:crypto`.
 *
 * Invariants:
 * - tokens carry 256 bits of randomness and are never stored, only hashed;
 * - secret content is sealed with AES-256-GCM under a random 96-bit nonce;
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
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
