/**
 * Secret lifecycle: create, anonymous control status, cancel, and single-use reveal.
 *
 * Consumption is a single `DELETE ... RETURNING` statement, so the database
 * itself guarantees that at most one concurrent request ever obtains the payload.
 * Expiry is evaluated with `now()` on the server side, never with a
 * client-supplied timestamp.
 *
 * Two layers of encryption sit on the stored ciphertext. The inner one is made by
 * the browser with a key that lives only in the share link fragment and is never
 * sent here; this module stores and returns that opaque `payload` verbatim. The
 * outer one is `encryptSecret` from `src/lib/crypto.ts`, under the deployment
 * key, so a database dump is still not the text.
 *
 * The browser derives an auth key from the fragment key and, when set, the
 * password, and sends its SHA-256 at creation. Every row stores `auth_hash`, an
 * HMAC-SHA256 of that hash under a subkey of the deployment key, so a database
 * dump without the deployment key cannot be used to test passwords offline, not
 * even together with the share link. A reveal must present the auth key before
 * the delete runs, so a wrong password or a damaged fragment key is refused
 * without consuming anything, and each guess costs one rate limited request.
 */
import { Buffer } from 'node:buffer';
import { createHash, timingSafeEqual } from 'node:crypto';
import { query, withClient } from './db.ts';
import { getConfig } from './env.ts';
import {
  TOKEN_LENGTH,
  decryptSecret,
  encryptSecret,
  generateToken,
  hashToken,
  isValidTokenShape,
  keyAuthHash,
} from './crypto.ts';
import {
  CONTENT_NONCE_BYTES,
  CONTENT_TAG_BYTES,
  PASSWORD_MAX_LENGTH,
  decodeAuthKey,
  isSealedEnvelope,
} from './content-crypto.ts';
import { RECEIPT_RETENTION_DAYS } from './cleanup.mjs';

export { RECEIPT_RETENTION_DAYS };

/** Unpadded base64url length of `byteLength` bytes. */
function base64UrlLength(byteLength: number): number {
  const remainder = byteLength % 3;
  return 4 * Math.floor(byteLength / 3) + (remainder === 0 ? 0 : remainder + 1);
}

/** Size of the secret text the browser is allowed to seal. */
export const MAX_SECRET_BYTES = 50 * 1024;

/**
 * Ceiling for the sealed payload the browser sends.
 *
 * The payload is `base64url(nonce || ciphertext || tag)` over a secret of at most
 * `MAX_SECRET_BYTES`, so the longest possible value is the unpadded base64url
 * length of `MAX_SECRET_BYTES + 12 + 16` bytes. Base64url never expands in JSON,
 * so this is also what the request body ceiling is built from.
 */
export const MAX_PAYLOAD_BYTES = base64UrlLength(MAX_SECRET_BYTES + CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES);

export const MAX_PASSWORD_LENGTH = PASSWORD_MAX_LENGTH;

/** Lowercase hex SHA-256 of the auth key, and the stored HMAC of it. */
const AUTH_HASH_SHAPE = /^[0-9a-f]{64}$/;
const AUTH_HASH_LENGTH = 64;

/** The only accepted expiries: a preset, never an arbitrary number of days. */
export const EXPIRY_PRESETS = ['1h', '1d', '7d', '30d'] as const;

export type ExpiryPreset = (typeof EXPIRY_PRESETS)[number];

export const DEFAULT_EXPIRY_PRESET: ExpiryPreset = '7d';

/** Seconds added to the database clock for each preset. */
export const EXPIRY_PRESET_SECONDS: Readonly<Record<ExpiryPreset, number>> = Object.freeze({
  '1h': 60 * 60,
  '1d': 24 * 60 * 60,
  '7d': 7 * 24 * 60 * 60,
  '30d': 30 * 24 * 60 * 60,
});

/**
 * Worst case size of a JSON field relative to its decoded text.
 *
 * `JSON.stringify` escapes quotes, backslashes and control characters, and a
 * control character becomes a six byte `\uXXXX` sequence. The payload is
 * base64url and never expands, so the factor applies to the password alone.
 */
const JSON_ESCAPE_FACTOR = 6;

/** Room for the field names, punctuation, the expiry preset and any slack. */
const JSON_ENVELOPE_BYTES = 256;

/**
 * Body ceiling for `POST /api/secrets`: a full size payload plus the auth hash.
 *
 * The password is not part of this body. It stays in the browser and is mixed
 * into the derived keys there.
 */
export const MAX_CREATE_BODY_BYTES = MAX_PAYLOAD_BYTES + AUTH_HASH_LENGTH + JSON_ENVELOPE_BYTES;

/**
 * Body ceiling for `POST /api/secrets/reveal`: a token and an auth key, never the
 * payload. Kept small on purpose so a reveal request cannot be used to push
 * megabytes of arbitrary content into the process.
 */
export const MAX_REVEAL_BODY_BYTES =
  2 * TOKEN_LENGTH * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

/** Body ceiling for `POST /api/secrets/cancel`: one control token and nothing else. */
export const MAX_CANCEL_BODY_BYTES = TOKEN_LENGTH * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

export type SecretErrorCode =
  | 'payloadRequired'
  | 'payloadTooLong'
  | 'invalidPayload'
  | 'invalidAuth'
  | 'invalidExpiry';

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
  /** Sealed secret text, produced by the browser. Never decrypted here. */
  readonly payload: string;
  readonly expiresIn: ExpiryPreset;
  /**
   * Hex SHA-256 of the browser-derived auth key. Required for every secret. It
   * is stored only as an HMAC under a subkey of the deployment key.
   */
  readonly authHash: string;
  /**
   * Whether the browser mixed a password into the keys. It only decides whether
   * the open page asks for one: the auth hash is what actually enforces it. The
   * password itself is never a field of this input.
   */
  readonly passwordProtected?: boolean;
}

export interface CreatedSecret {
  readonly token: string;
  readonly controlToken: string;
  readonly expiresAt: Date;
}

export type PasswordMode = 'none' | 'client';

/** `bad_key` is a failed auth key on a secret without a password. */
export type RevealFailure = 'unavailable' | 'bad_password' | 'bad_key' | 'undecryptable';

export type RevealResult =
  | { readonly ok: true; readonly payload: string }
  | { readonly ok: false; readonly reason: RevealFailure };

/** What a control link reports. `pending` is the only cancellable state. */
export type ControlState = 'pending' | 'read' | 'expired' | 'cancelled';

export interface ControlStatus {
  readonly state: ControlState;
  readonly expiresAt: Date | null;
  /**
   * When the secret was created. Present while the row is live, and absent once
   * it is gone: a receipt deliberately keeps no creation instant, because the
   * row it describes no longer exists.
   */
  readonly createdAt: Date | null;
  /**
   * When the secret actually closed, which for a receipt is the moment the row
   * was deleted. Null while the secret is still pending, since it has not closed
   * yet.
   */
  readonly closedAt: Date | null;
}

export type CancelResult =
  | { readonly ok: true; readonly status: ControlStatus }
  | { readonly ok: false; readonly reason: 'unavailable' };

interface SecretRow {
  ciphertext: string;
  auth_hash: string;
  has_password: boolean;
}

interface ConsumedRow {
  control_hash: string | null;
  expires_at: Date;
}

interface ControlStatusRow {
  live_created_at: Date | null;
  live_expires_at: Date | null;
  live_is_expired: boolean | null;
  receipt_state: ControlState | null;
  receipt_expires_at: Date | null;
  receipt_closed_at: Date | null;
}

/**
 * Writes the close receipt for a secret that this transaction has just removed.
 *
 * The statement is intentionally free of `ON CONFLICT`: a receipt can only be
 * written by the same transaction that deleted the row, so a conflict would mean
 * two closers agreed to close one secret. Failing there aborts the transaction
 * and leaves the row in place, which is the recoverable outcome.
 */
const RECEIPT_INSERT = `
  INSERT INTO secret_receipts (control_hash, state, expires_at, closed_at, purge_after)
  VALUES ($1, $2::text, $3::timestamptz, now(),
          GREATEST($3::timestamptz, now() + make_interval(days => $4::int)))`;

function validatePayload(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length === 0) {
    throw new SecretValidationError('payloadRequired', 'Payload must be a non-empty string');
  }
  const byteLength = Buffer.byteLength(raw, 'utf8');
  if (byteLength > MAX_PAYLOAD_BYTES) {
    throw new SecretValidationError(
      'payloadTooLong',
      `Payload is ${byteLength} bytes, limit is ${MAX_PAYLOAD_BYTES}`,
    );
  }
  const maxDecoded = MAX_SECRET_BYTES + CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES;
  if (!isSealedEnvelope(raw, maxDecoded)) {
    throw new SecretValidationError('invalidPayload', 'Payload is not a sealed envelope');
  }
  return raw;
}

function validateAuthHash(raw: unknown): string {
  if (typeof raw !== 'string' || !AUTH_HASH_SHAPE.test(raw)) {
    throw new SecretValidationError('invalidAuth', 'Auth hash must be 64 lowercase hex characters');
  }
  return raw;
}

function validatePasswordFlag(raw: unknown): boolean {
  if (raw === undefined) return false;
  if (typeof raw !== 'boolean') {
    throw new SecretValidationError('invalidAuth', 'Password flag must be a boolean');
  }
  return raw;
}

/** Stored form of a well formed auth key, or `null` when the text is not one. */
function storedAuthHashForKey(raw: unknown, encryptionKey: Buffer): string | null {
  const bytes = decodeAuthKey(raw);
  return bytes ? keyAuthHash(createHash('sha256').update(bytes).digest(), encryptionKey) : null;
}

/** Only the four presets pass. No coercion: `7` is not `7d`. */
function validateExpiryPreset(raw: unknown): ExpiryPreset {
  if (typeof raw !== 'string' || !(EXPIRY_PRESETS as readonly string[]).includes(raw)) {
    throw new SecretValidationError(
      'invalidExpiry',
      `Expiry must be one of ${EXPIRY_PRESETS.join(', ')}`,
    );
  }
  return raw as ExpiryPreset;
}

export async function createSecret(input: CreateSecretInput): Promise<CreatedSecret> {
  const payload = validatePayload(input.payload);
  const expiresIn = validateExpiryPreset(input.expiresIn);
  const authHash = validateAuthHash(input.authHash);
  const hasPassword = validatePasswordFlag(input.passwordProtected);

  const token = generateToken();
  const controlToken = generateToken();
  const tokenHash = hashToken(token);
  const controlHash = hashToken(controlToken);
  // The payload is opaque here: the inner key never reaches the server, so this
  // layer protects the stored value without ever being able to open it.
  const key = getConfig().encryptionKey;
  const ciphertext = encryptSecret(payload, key);
  const storedAuthHash = keyAuthHash(Buffer.from(authHash, 'hex'), key);

  const { rows } = await query<{ expires_at: Date }>(
    `INSERT INTO secrets (token_hash, control_hash, ciphertext, auth_hash, has_password, expires_at)
     VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6::double precision))
     RETURNING expires_at`,
    [tokenHash, controlHash, ciphertext, storedAuthHash, hasPassword, EXPIRY_PRESET_SECONDS[expiresIn]],
  );

  const expiresAt = rows[0]?.expires_at;
  if (!expiresAt) throw new Error('Secret insert returned no row');
  return { token, controlToken, expiresAt: new Date(expiresAt) };
}

export async function peekSecretPresence(token: string): Promise<{ password: PasswordMode } | null> {
  if (!isValidTokenShape(token)) return null;
  const { rows } = await query<{ has_password: boolean; is_expired: boolean }>(
    `SELECT has_password, expires_at <= now() AS is_expired
       FROM secrets
      WHERE token_hash = $1`,
    [hashToken(token)],
  );
  const row = rows[0];
  if (!row || row.is_expired) return null;
  return { password: row.has_password ? 'client' : 'none' };
}

/**
 * Report the state of a control link, consuming nothing and decrypting nothing.
 *
 * Both lookups share one statement, so the row and its receipt are read from a
 * single snapshot: a reveal committed between them cannot leave a gap in which
 * neither is visible. A `null` result covers an unknown token and a receipt that
 * has already been purged, and the page answers both the same way.
 */
export async function readControlStatus(controlToken: string): Promise<ControlStatus | null> {
  if (!isValidTokenShape(controlToken)) return null;
  const controlHash = hashToken(controlToken);

  const { rows } = await query<ControlStatusRow>(
    `SELECT live.created_at AS live_created_at,
            live.expires_at AS live_expires_at,
            (live.expires_at <= now()) AS live_is_expired,
            receipt.state AS receipt_state,
            receipt.expires_at AS receipt_expires_at,
            receipt.closed_at AS receipt_closed_at
       FROM (SELECT 1) AS anchor
       LEFT JOIN LATERAL (
         SELECT s.created_at, s.expires_at FROM secrets s WHERE s.control_hash = $1
       ) AS live ON true
       LEFT JOIN LATERAL (
         SELECT r.state, r.expires_at, r.closed_at
           FROM secret_receipts r WHERE r.control_hash = $1
       ) AS receipt ON true`,
    [controlHash],
  );

  const row = rows[0];
  if (!row) return null;

  // A live row decides the answer. Expiry is judged by the database clock: the
  // cleanup job may not have removed the row yet, and that is not observable.
  if (row.live_expires_at) {
    return {
      state: row.live_is_expired === true ? 'expired' : 'pending',
      expiresAt: row.live_expires_at,
      createdAt: row.live_created_at,
      closedAt: null,
    };
  }
  if (row.receipt_state) {
    return {
      state: row.receipt_state,
      expiresAt: row.receipt_expires_at,
      // The row is gone, so there is no creation instant left to report. The
      // receipt only knows when it closed.
      createdAt: null,
      closedAt: row.receipt_closed_at,
    };
  }
  return null;
}

/**
 * Cancel a secret before anybody has read it.
 *
 * The delete is conditional on the row still being live, so a cancel that loses a
 * race with a reveal deletes nothing and reports the state from the receipt the
 * reveal wrote. Both closers run the same shape of transaction and neither holds
 * a lock across any password check, so exactly one outcome survives.
 */
export async function cancelSecret(controlToken: string): Promise<CancelResult> {
  if (!isValidTokenShape(controlToken)) return { ok: false, reason: 'unavailable' };
  const controlHash = hashToken(controlToken);

  await withClient(async (client) => {
    await client.query('BEGIN');
    try {
      const { rows } = await client.query<{ expires_at: Date }>(
        `DELETE FROM secrets
          WHERE control_hash = $1
            AND expires_at > now()
          RETURNING expires_at`,
        [controlHash],
      );
      const row = rows[0];
      if (row) {
        await client.query(RECEIPT_INSERT, [controlHash, 'cancelled', row.expires_at, RECEIPT_RETENTION_DAYS]);
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  // Nothing was deleted here, so the authoritative answer is the receipt, which
  // for a still live secret is the `pending` status just read back.
  const status = await readControlStatus(controlToken);
  if (!status) return { ok: false, reason: 'unavailable' };
  return { ok: true, status };
}

/**
 * Reveal a payload exactly once.
 *
 * Sequence: read the row without a lock, check the auth key against the stored
 * keyed hash and decrypt the outer layer that was just read, both outside any
 * transaction, and only then attempt the atomic conditional delete that also
 * writes the close receipt.
 *
 * A wrong auth key means a wrong password or a damaged fragment key: either way
 * the browser could not open the payload, so the row stays. The password key
 * derivation happens in the browser, so no lock is ever held across it.
 *
 * Decryption comes before the delete on purpose. A wrong deployment key or a
 * corrupted ciphertext makes the GCM tag fail, and deleting first would destroy
 * a secret that nobody has read yet. A failure here is reported as
 * `undecryptable` and the row is left in place: restoring the key makes the
 * link work again.
 *
 * The stored hash is keyed by the same deployment key, so a wrong deployment key
 * also fails the auth comparison. Decryption therefore decides first: a GCM
 * failure reports `undecryptable`, never a password error the user cannot fix.
 */
export async function revealSecret(token: string, authKey: unknown): Promise<RevealResult> {
  if (!isValidTokenShape(token)) return { ok: false, reason: 'unavailable' };

  const tokenHash = hashToken(token);

  const { rows: candidates } = await query<SecretRow>(
    `SELECT ciphertext, auth_hash, has_password
       FROM secrets
      WHERE token_hash = $1
        AND expires_at > now()`,
    [tokenHash],
  );
  const candidate = candidates[0];
  if (!candidate) return { ok: false, reason: 'unavailable' };

  const encryptionKey = getConfig().encryptionKey;
  const presented = storedAuthHashForKey(authKey, encryptionKey);
  const authorized = presented !== null &&
    timingSafeEqual(Buffer.from(presented, 'hex'), Buffer.from(candidate.auth_hash, 'hex'));

  // A wrong key or a tampered payload lands here. Nothing is logged: the
  // ciphertext, the token, the auth key and the payload are all off limits.
  let payload: string;
  try {
    payload = decryptSecret(candidate.ciphertext, encryptionKey);
  } catch {
    return { ok: false, reason: 'undecryptable' };
  }

  if (!authorized) {
    return { ok: false, reason: candidate.has_password ? 'bad_password' : 'bad_key' };
  }

  const consumed = await withClient(async (client) => {
    await client.query('BEGIN');
    try {
      // Guarding on the verified hash as well keeps the delete tied to the
      // credential that was just checked, not only to the token.
      const { rows } = await client.query<ConsumedRow>(
        `DELETE FROM secrets
          WHERE token_hash = $1
            AND expires_at > now()
            AND auth_hash = $2
          RETURNING control_hash, expires_at`,
        [tokenHash, candidate.auth_hash],
      );
      const row = rows[0];
      if (row?.control_hash) {
        await client.query(RECEIPT_INSERT, [row.control_hash, 'read', row.expires_at, RECEIPT_RETENTION_DAYS]);
      }
      await client.query('COMMIT');
      return row;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    }
  });

  // No row means a concurrent request won the race, or the secret expired between
  // the read and the delete. Either way this caller gets nothing and the payload
  // it already holds is discarded.
  if (!consumed) return { ok: false, reason: 'unavailable' };
  return { ok: true, payload };
}
