/**
 * Shared fixtures and raw-SQL probes.
 *
 * Helpers intentionally create their own data so that tests stay independent of
 * execution order; nothing here returns secret content, passwords or tokens.
 */
import { Buffer } from 'node:buffer';
import { hashPassword, hashToken } from '../src/lib/crypto.ts';
import { query } from '../src/lib/db.ts';
import {
  PASSWORD_VERIFIER_TEXT,
  encodeContentKey,
  encodeShareFragment,
  encryptPayload,
  generateContentKey,
  generatePasswordSalt,
  derivePasswordKey,
  type ContentBytes,
} from '../src/lib/content-crypto.ts';
import { SecretValidationError } from '../src/lib/secrets.ts';

// Tests import the setup helper from here so they only need one fixture module.
export { resetEnv } from './setup.ts';

export interface SecretRow {
  token_hash: string;
  control_hash: string;
  ciphertext: string;
  password_hash: string | null;
  password_verifier: string | null;
  expires_at: Date;
  created_at: Date;
}

export interface ReceiptRow {
  control_hash: string;
  state: 'read' | 'expired' | 'cancelled';
  expires_at: Date;
  closed_at: Date;
  purge_after: Date;
}

export interface RateLimitRow {
  bucket: string;
  subject: string;
  window_started_at: Date;
  hits: number;
}

export async function fetchSecretRow(token: string): Promise<SecretRow | undefined> {
  const { rows } = await query<SecretRow>(
    `SELECT token_hash, control_hash, ciphertext, password_hash, password_verifier, expires_at, created_at
       FROM secrets
      WHERE token_hash = $1`,
    [hashToken(token)],
  );
  return rows[0];
}

/** The whole row serialized, to assert that nothing sensitive leaks into it. */
export async function secretRowJson(token: string): Promise<string> {
  const { rows } = await query<{ json: string }>(
    `SELECT row_to_json(s)::text AS json FROM secrets s WHERE s.token_hash = $1`,
    [hashToken(token)],
  );
  return rows[0]?.json ?? '';
}

export async function countSecrets(): Promise<number> {
  const { rows } = await query<{ count: string }>('SELECT count(*)::text AS count FROM secrets');
  return Number.parseInt(rows[0]?.count ?? '0', 10);
}

export async function fetchReceipt(controlToken: string): Promise<ReceiptRow | undefined> {
  const { rows } = await query<ReceiptRow>(
    `SELECT control_hash, state, expires_at, closed_at, purge_after
       FROM secret_receipts
      WHERE control_hash = $1`,
    [hashToken(controlToken)],
  );
  return rows[0];
}

export async function fetchReceiptJson(controlToken: string): Promise<string> {
  const { rows } = await query<{ json: string }>(
    `SELECT row_to_json(r)::text AS json FROM secret_receipts r WHERE r.control_hash = $1`,
    [hashToken(controlToken)],
  );
  return rows[0]?.json ?? '';
}

export async function countReceipts(): Promise<number> {
  const { rows } = await query<{ count: string }>(
    'SELECT count(*)::text AS count FROM secret_receipts',
  );
  return Number.parseInt(rows[0]?.count ?? '0', 10);
}

/** Move a receipt's purge date into the past, as the passage of time would. */
export async function forceReceiptPurge(controlToken: string): Promise<void> {
  await query(
    `UPDATE secret_receipts
        SET purge_after = now() - interval '1 minute'
      WHERE control_hash = $1`,
    [hashToken(controlToken)],
  );
}

/** Remove a receipt outright, as a cleanup job that has caught up would. */
export async function deleteReceipt(controlToken: string): Promise<void> {
  await query('DELETE FROM secret_receipts WHERE control_hash = $1', [hashToken(controlToken)]);
}

export async function fetchRateLimitRows(
  bucket: string,
  subject: string,
): Promise<RateLimitRow[]> {
  const { rows } = await query<RateLimitRow>(
    `SELECT bucket, subject, window_started_at, hits
       FROM rate_limits
      WHERE bucket = $1 AND subject = $2`,
    [bucket, subject],
  );
  return rows;
}

export async function countRateLimits(): Promise<number> {
  const { rows } = await query<{ count: string }>('SELECT count(*)::text AS count FROM rate_limits');
  return Number.parseInt(rows[0]?.count ?? '0', 10);
}

export async function insertRateLimitRow(
  bucket: string,
  subject: string,
  ageSeconds: number,
  hits = 1,
): Promise<void> {
  await query(
    `INSERT INTO rate_limits (bucket, subject, window_started_at, hits)
     VALUES ($1, $2, now() - make_interval(secs => $3::double precision), $4)`,
    [bucket, subject, ageSeconds, hits],
  );
}

/** Push a secret's expiry into the past without touching application code. */
export async function forceExpire(token: string): Promise<void> {
  await query(`UPDATE secrets SET expires_at = now() - interval '1 minute' WHERE token_hash = $1`, [
    hashToken(token),
  ]);
}

/** Move the expiry to an absolute offset from the database clock. */
export async function setExpiresInSeconds(token: string, seconds: number): Promise<void> {
  await query(
    `UPDATE secrets SET expires_at = now() + make_interval(secs => $2::double precision)
      WHERE token_hash = $1`,
    [hashToken(token), seconds],
  );
}

export async function tableExists(name: string): Promise<boolean> {
  const { rows } = await query<{ regclass: string | null }>(
    'SELECT to_regclass($1)::text AS regclass',
    [`public.${name}`],
  );
  return rows[0]?.regclass != null;
}

/** A payload of an exact UTF-8 byte length, built mostly from 3-byte characters. */
export function payloadOfBytes(byteLength: number): string {
  const wide = '\u20AC';
  const triples = Math.floor(byteLength / 3);
  return wide.repeat(triples) + 'a'.repeat(byteLength - triples * 3);
}

export function utf8(value: string): Buffer {
  return Buffer.from(value, 'utf8');
}

/** A payload that is valid to store but carries no readable text of its own. */
export function fakePayload(secret: string): string {
  return `not-really-sealed:${secret.length}:${Buffer.from(secret, 'utf8').toString('base64url')}`;
}

/**
 * Seal a secret the way the browser does and hand back everything a test needs to
 * act as the client: the opaque payload the server stores, the key, and the text
 * form that travels in the link fragment.
 */
export async function sealedSecret(secret: string): Promise<{
  payload: string;
  key: ContentBytes;
  keyText: string;
}> {
  const key = generateContentKey();
  return { payload: await encryptPayload(secret, key), key, keyText: encodeContentKey(key) };
}

/** A well formed verifier envelope. It does not bind a particular password. */
export async function dummyVerifier(): Promise<string> {
  return encryptPayload(PASSWORD_VERIFIER_TEXT, generateContentKey());
}

/**
 * Seal a secret the way the password form does: the payload and the verifier
 * share a key derived from the fragment key and the password.
 */
export async function sealedPasswordSecret(
  secret: string,
  password: string,
): Promise<{
  payload: string;
  verifier: string;
  key: ContentBytes;
  salt: ContentBytes;
  fragment: string;
}> {
  const key = generateContentKey();
  const salt = generatePasswordSalt();
  const derived = await derivePasswordKey(key, password, salt);
  return {
    payload: await encryptPayload(secret, derived),
    verifier: await encryptPayload(PASSWORD_VERIFIER_TEXT, derived),
    key,
    salt,
    fragment: encodeShareFragment(key, salt),
  };
}

/** Attach a legacy scrypt hash to a row created without a client verifier. */
export async function lockWithLegacyPassword(token: string, password: string): Promise<void> {
  await query(`UPDATE secrets SET password_hash = $2 WHERE token_hash = $1`, [
    hashToken(token),
    await hashPassword(password),
  ]);
}

/** The share link a recipient receives, key included: it never leaves the browser. */
export function shareLink(base: string, token: string, keyText: string): string {
  return `${base}/s/${token}#${keyText}`;
}

/** Await a rejected `createSecret` and return the typed validation error. */
export async function captureSecretError(promise: Promise<unknown>): Promise<SecretValidationError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof SecretValidationError) return error;
    throw error;
  }
  throw new Error('Expected createSecret to reject, but it resolved');
}
