/**
 * Secret lifecycle: create, and single-use reveal.
 *
 * Consumption is a single `DELETE ... RETURNING` statement, so the database
 * itself guarantees that at most one concurrent request ever obtains the
 * ciphertext. Expiry is evaluated with `now()` on the server side, never with a
 * client-supplied timestamp.
 */
import { Buffer } from 'node:buffer';
import { query } from './db.ts';
import { getConfig } from './env.ts';
import {
  TOKEN_LENGTH,
  decryptSecret,
  encryptSecret,
  generateToken,
  hashPassword,
  hashToken,
  isValidTokenShape,
  verifyPassword,
} from './crypto.ts';

export const MAX_SECRET_BYTES = 50 * 1024;
export const MIN_EXPIRY_DAYS = 1;
export const MAX_EXPIRY_DAYS = 30;
export const DEFAULT_EXPIRY_DAYS = 7;
export const MAX_PASSWORD_LENGTH = 512;

/**
 * Worst case size of a JSON field relative to its decoded text.
 *
 * `JSON.stringify` escapes quotes, backslashes and control characters, and a
 * control character becomes a six byte `\uXXXX` sequence. A 50 KiB secret made
 * of control characters is therefore 300 KiB on the wire, so a body cap sized for
 * plain text would answer `badRequest` to a perfectly legitimate secret. The
 * factor is applied to the decoded limits, which is where the real limits live.
 */
const JSON_ESCAPE_FACTOR = 6;

/** Room for the field names, punctuation, the expiry number and any slack. */
const JSON_ENVELOPE_BYTES = 256;

/** Body ceiling for `POST /api/secrets`: a full size secret plus a full size password. */
export const MAX_CREATE_BODY_BYTES =
  (MAX_SECRET_BYTES + MAX_PASSWORD_LENGTH) * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

/**
 * Body ceiling for `POST /api/secrets/reveal`: a token and a password, never
 * the secret. Kept small on purpose so a reveal request cannot be used to push
 * megabytes of arbitrary content into the process.
 */
export const MAX_REVEAL_BODY_BYTES =
  (TOKEN_LENGTH + MAX_PASSWORD_LENGTH) * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

export type SecretErrorCode =
  | 'secretRequired'
  | 'secretTooLong'
  | 'invalidExpiry'
  | 'passwordTooLong';

export class SecretValidationError extends Error {
  constructor(
    readonly code: SecretErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'SecretValidationError';
  }
}

export interface CreateSecretInput {
  readonly secret: string;
  readonly expiresInDays: number;
  readonly password?: string;
}

export interface CreatedSecret {
  readonly token: string;
  readonly expiresAt: Date;
}

export type RevealFailure = 'unavailable' | 'bad_password' | 'undecryptable';

export type RevealResult =
  | { readonly ok: true; readonly secret: string }
  | { readonly ok: false; readonly reason: RevealFailure };

interface SecretRow {
  ciphertext: string;
  password_hash: string | null;
}

/** Trim nothing: the secret is stored and returned byte for byte. */
function validateSecret(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new SecretValidationError('secretRequired', 'Secret must be a non-empty string');
  }
  const byteLength = Buffer.byteLength(raw, 'utf8');
  if (byteLength > MAX_SECRET_BYTES) {
    throw new SecretValidationError(
      'secretTooLong',
      `Secret is ${byteLength} bytes, limit is ${MAX_SECRET_BYTES}`,
    );
  }
  return raw;
}

function validateExpiryDays(raw: unknown): number {
  const days = typeof raw === 'string' ? Number(raw) : raw;
  if (
    typeof days !== 'number' ||
    !Number.isInteger(days) ||
    days < MIN_EXPIRY_DAYS ||
    days > MAX_EXPIRY_DAYS
  ) {
    throw new SecretValidationError(
      'invalidExpiry',
      `Expiry must be an integer between ${MIN_EXPIRY_DAYS} and ${MAX_EXPIRY_DAYS} days`,
    );
  }
  return days;
}

function validatePassword(raw: unknown): string | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'string') {
    throw new SecretValidationError('passwordTooLong', 'Password must be a string');
  }
  const password = raw.normalize('NFKC');
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new SecretValidationError(
      'passwordTooLong',
      `Password is ${password.length} characters, limit is ${MAX_PASSWORD_LENGTH}`,
    );
  }
  return password;
}

export async function createSecret(input: CreateSecretInput): Promise<CreatedSecret> {
  const secret = validateSecret(input.secret);
  const days = validateExpiryDays(input.expiresInDays);
  const password = validatePassword(input.password);

  const token = generateToken();
  const tokenHash = hashToken(token);
  const ciphertext = encryptSecret(secret, getConfig().encryptionKey);
  // Hash the password before touching the database: no lock is held during scrypt.
  const passwordHash = password === undefined ? null : await hashPassword(password);

  const { rows } = await query<{ expires_at: Date }>(
    `INSERT INTO secrets (token_hash, ciphertext, password_hash, expires_at)
     VALUES ($1, $2, $3, now() + make_interval(days => $4::int))
     RETURNING expires_at`,
    [tokenHash, ciphertext, passwordHash, days],
  );

  const expiresAt = rows[0]?.expires_at;
  if (!expiresAt) throw new Error('Secret insert returned no row');
  return { token, expiresAt: new Date(expiresAt) };
}

export async function peekSecretPresence(token: string): Promise<{ requiresPassword: boolean } | null> {
  if (!isValidTokenShape(token)) return null;
  const { rows } = await query<{ password_hash: string | null; is_expired: boolean }>(
    `SELECT password_hash,
            expires_at <= now() AS is_expired
       FROM secrets
      WHERE token_hash = $1`,
    [hashToken(token)],
  );
  const row = rows[0];
  if (!row || row.is_expired) return null;
  return { requiresPassword: row.password_hash !== null };
}

/**
 * Reveal a secret exactly once.
 *
 * Sequence: read the row without a lock, verify the password outside any
 * transaction, decrypt the ciphertext that was just read, and only then attempt
 * the atomic conditional delete.
 *
 * Decryption comes before the delete on purpose. A wrong key or a corrupted
 * ciphertext makes the GCM tag fail, and deleting first would destroy a secret
 * that nobody has read yet. A failure here is reported as `undecryptable` and
 * the row is left in place: restoring the key makes the link work again.
 *
 * A failing password never reaches the decrypt or the delete, so it cannot
 * consume the secret.
 */
export async function revealSecret(token: string, password?: string): Promise<RevealResult> {
  if (!isValidTokenShape(token)) return { ok: false, reason: 'unavailable' };

  const tokenHash = hashToken(token);

  const { rows: candidates } = await query<SecretRow>(
    `SELECT ciphertext, password_hash
       FROM secrets
      WHERE token_hash = $1
        AND expires_at > now()`,
    [tokenHash],
  );
  const candidate = candidates[0];
  if (!candidate) return { ok: false, reason: 'unavailable' };

  if (candidate.password_hash !== null) {
    const supplied = password ?? '';
    if (!(await verifyPassword(supplied, candidate.password_hash))) {
      return { ok: false, reason: 'bad_password' };
    }
  }

  // A wrong key or a tampered payload lands here. Nothing is logged: the
  // ciphertext, the token, the password and the plaintext are all off limits.
  let plaintext: string;
  try {
    plaintext = decryptSecret(candidate.ciphertext, getConfig().encryptionKey);
  } catch {
    return { ok: false, reason: 'undecryptable' };
  }

  const { rows: consumed } = await query<{ ciphertext: string }>(
    `DELETE FROM secrets
      WHERE token_hash = $1
        AND expires_at > now()
      RETURNING ciphertext`,
    [tokenHash],
  );
  const row = consumed[0];
  // Zero rows means a concurrent request won the race, or the secret expired
  // between the read and the delete. Either way this caller gets nothing and the
  // plaintext it already holds is discarded.
  if (!row) return { ok: false, reason: 'unavailable' };

  if (row.ciphertext !== candidate.ciphertext) {
    // Unreachable today: the delete is the only writer of this column and
    // nothing updates it in place, so the two values are always the same string.
    // The row is gone either way, so refusing here would report a consumed
    // secret as unavailable and destroy it. The deleted payload is the one this
    // caller has just consumed, so decrypt that instead of discarding it.
    try {
      return { ok: true, secret: decryptSecret(row.ciphertext, getConfig().encryptionKey) };
    } catch {
      return { ok: false, reason: 'undecryptable' };
    }
  }

  return { ok: true, secret: plaintext };
}

/** Remove expired secrets and stale rate limit counters. */
export async function purgeExpired(olderThanSeconds: number): Promise<{ secrets: number; counters: number }> {
  const secrets = await query<{ count: string }>(
    `WITH deleted AS (
       DELETE FROM secrets WHERE expires_at <= now() RETURNING 1
     )
     SELECT count(*)::text AS count FROM deleted`,
  );
  const counters = await query<{ count: string }>(
    `WITH deleted AS (
       DELETE FROM rate_limits
        WHERE window_started_at <= now() - make_interval(secs => $1::double precision)
        RETURNING 1
     )
     SELECT count(*)::text AS count FROM deleted`,
    [olderThanSeconds],
  );
  return {
    secrets: Number.parseInt(secrets.rows[0]?.count ?? '0', 10),
    counters: Number.parseInt(counters.rows[0]?.count ?? '0', 10),
  };
}