/**
 * Shared fixtures and raw-SQL probes.
 *
 * Helpers intentionally create their own data so that tests stay independent of
 * execution order; nothing here returns secret content, passwords or tokens.
 */
import { Buffer } from 'node:buffer';
import { hashToken } from '../src/lib/crypto.ts';
import { query } from '../src/lib/db.ts';
import { SecretValidationError } from '../src/lib/secrets.ts';

// Tests import the setup helper from here so they only need one fixture module.
export { resetEnv } from './setup.ts';

export interface SecretRow {
  token_hash: string;
  ciphertext: string;
  password_hash: string | null;
  expires_at: Date;
  created_at: Date;
}

export interface RateLimitRow {
  bucket: string;
  subject: string;
  window_started_at: Date;
  hits: number;
}

export async function fetchSecretRow(token: string): Promise<SecretRow | undefined> {
  const { rows } = await query<SecretRow>(
    `SELECT token_hash, ciphertext, password_hash, expires_at, created_at
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
