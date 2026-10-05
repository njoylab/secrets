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
 */
import { Buffer } from 'node:buffer';
import { timingSafeEqual } from 'node:crypto';
import { query, withClient } from './db.ts';
import { getConfig } from './env.ts';
import {
  TOKEN_LENGTH,
  decryptSecret,
  encryptSecret,
  generateToken,
  hashToken,
  isValidTokenShape,
} from './crypto.ts';
import {
  CONTENT_NONCE_BYTES,
  CONTENT_TAG_BYTES,
  PASSWORD_MAX_LENGTH,
  isSealedEnvelope,
} from './content-crypto.ts';

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

/**
 * Largest sealed verifier the browser may store.
 *
 * The verifier plaintext carries a short prefix and a random reveal proof.
 * The ceiling refuses a second copy of the secret smuggled in this field.
 */
const MAX_VERIFIER_PLAINTEXT_BYTES = 128;
const MAX_VERIFIER_DECODED = CONTENT_NONCE_BYTES + CONTENT_TAG_BYTES + MAX_VERIFIER_PLAINTEXT_BYTES;
export const MAX_VERIFIER_BYTES = base64UrlLength(MAX_VERIFIER_DECODED);

/** How long a receipt is kept after the secret closed. */
export const RECEIPT_RETENTION_DAYS = 7;

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
 * Body ceiling for `POST /api/secrets`: a full size payload plus a verifier.
 *
 * The password is not part of this body. It stays in the browser and is mixed
 * into the content key there.
 */
export const MAX_CREATE_BODY_BYTES = MAX_PAYLOAD_BYTES + MAX_VERIFIER_BYTES + JSON_ENVELOPE_BYTES;

/**
 * Body ceiling for `POST /api/secrets/reveal`: a token and a reveal proof, never the
 * payload. Kept small on purpose so a reveal request cannot be used to push
 * megabytes of arbitrary content into the process.
 */
export const MAX_REVEAL_BODY_BYTES =
  2 * TOKEN_LENGTH * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

/** Body ceiling for `POST /api/secrets/cancel`: one control token and nothing else. */
export const MAX_CANCEL_BODY_BYTES = TOKEN_LENGTH * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

/** Body ceiling for `POST /api/secrets/verifier`: one share token and nothing else. */
export const MAX_VERIFIER_BODY_BYTES = TOKEN_LENGTH * JSON_ESCAPE_FACTOR + JSON_ENVELOPE_BYTES;

export type SecretErrorCode =
  | 'payloadRequired'
  | 'payloadTooLong'
  | 'invalidPayload'
  | 'invalidVerifier'
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
   * Sealed password check, produced by the browser under the same key as the
   * payload. Absent when the secret has no password. The password itself is
   * never a field of this input.
   */
  readonly verifier?: string;
  readonly revealProofHash?: string;
}

export interface CreatedSecret {
  readonly token: string;
  readonly controlToken: string;
  readonly expiresAt: Date;
}

export type PasswordMode = 'none' | 'client';

export type RevealFailure = 'unavailable' | 'bad_password' | 'undecryptable';

export type RevealResult =
  | { readonly ok: true; readonly payload: string }
  | { readonly ok: false; readonly reason: RevealFailure };

/** What a control link reports. `pending` is the only cancellable state. */
export type ControlState = 'pending' | 'read' | 'expired' | 'cancelled';

export interface ControlStatus {
  readonly state: ControlState;
  readonly expiresAt: Date | null;
}

export type CancelResult =
  | { readonly ok: true; readonly status: ControlStatus }
  | { readonly ok: false; readonly reason: 'unavailable' };

interface SecretRow {
  ciphertext: string;
  password_hash: string | null;
  password_verifier: string | null;
  reveal_proof_hash: string | null;
}

interface ConsumedRow {
  ciphertext: string;
  control_hash: string | null;
  expires_at: Date;
}

interface ControlStatusRow {
  live_expires_at: Date | null;
  live_is_expired: boolean | null;
  receipt_state: ControlState | null;
  receipt_expires_at: Date | null;
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

/** A browser verifier, or `undefined` when the secret has no password. */
function validateVerifier(raw: unknown): string | undefined {
  if (raw === undefined || raw === null || raw === '') return undefined;
  if (typeof raw !== 'string') {
    throw new SecretValidationError('invalidVerifier', 'Verifier must be a string');
  }
  const byteLength = Buffer.byteLength(raw, 'utf8');
  if (byteLength > MAX_VERIFIER_BYTES || !isSealedEnvelope(raw, MAX_VERIFIER_DECODED)) {
    throw new SecretValidationError('invalidVerifier', 'Verifier is not a sealed envelope');
  }
  return raw;
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
  const verifier = validateVerifier(input.verifier);
  const proofHash = input.revealProofHash;
  if ((verifier !== undefined && (typeof proofHash !== 'string' || !/^[0-9a-f]{64}$/.test(proofHash))) ||
      (verifier === undefined && proofHash !== undefined)) {
    throw new SecretValidationError('invalidVerifier', 'Invalid reveal proof hash');
  }

  const token = generateToken();
  const controlToken = generateToken();
  const tokenHash = hashToken(token);
  const controlHash = hashToken(controlToken);
  // The payload is opaque here: the inner key never reaches the server, so this
  // layer protects the stored value without ever being able to open it.
  const key = getConfig().encryptionKey;
  const ciphertext = encryptSecret(payload, key);
  // The verifier is the same kind of opaque envelope. Wrapping it keeps a
  // database dump from using it as an offline password oracle on its own.
  const verifierCiphertext = verifier === undefined ? null : encryptSecret(verifier, key);

  const { rows } = await query<{ expires_at: Date }>(
    `INSERT INTO secrets (token_hash, control_hash, ciphertext, password_hash, password_verifier, expires_at, reveal_proof_hash)
     VALUES ($1, $2, $3, NULL, $4, now() + make_interval(secs => $5::double precision), $6)
     RETURNING expires_at`,
    [tokenHash, controlHash, ciphertext, verifierCiphertext, EXPIRY_PRESET_SECONDS[expiresIn], proofHash ?? null],
  );

  const expiresAt = rows[0]?.expires_at;
  if (!expiresAt) throw new Error('Secret insert returned no row');
  return { token, controlToken, expiresAt: new Date(expiresAt) };
}

export async function peekSecretPresence(token: string): Promise<{ password: PasswordMode } | null> {
  if (!isValidTokenShape(token)) return null;
  const { rows } = await query<{
    password_hash: string | null;
    password_verifier: string | null;
    reveal_proof_hash: string | null;
    is_expired: boolean;
  }>(
    `SELECT password_hash,
            password_verifier,
            reveal_proof_hash,
            expires_at <= now() AS is_expired
       FROM secrets
      WHERE token_hash = $1`,
    [hashToken(token)],
  );
  const row = rows[0];
  if (!row || row.is_expired) return null;
  if (row.password_hash !== null ||
      (row.password_verifier === null) !== (row.reveal_proof_hash === null)) return null;
  if (row.password_verifier !== null) return { password: 'client' };
  return { password: 'none' };
}

export type VerifierRead =
  | { readonly ok: true; readonly verifier: string }
  | { readonly ok: false; readonly reason: 'unavailable' | 'undecryptable' };

/**
 * Return the password verifier without deleting the secret.
 *
 * The browser decrypts this blob with the password-derived key before it asks
 * to reveal. A wrong password stops there, so the row stays. The blob is not
 * the secret: revealing still requires the deleting statement.
 */
export async function readPasswordVerifier(token: string): Promise<VerifierRead> {
  if (!isValidTokenShape(token)) return { ok: false, reason: 'unavailable' };
  const { rows } = await query<{ password_verifier: string | null }>(
    `SELECT password_verifier
       FROM secrets
      WHERE token_hash = $1
        AND password_hash IS NULL
        AND reveal_proof_hash IS NOT NULL
        AND expires_at > now()`,
    [hashToken(token)],
  );
  const stored = rows[0]?.password_verifier;
  if (!stored) return { ok: false, reason: 'unavailable' };
  try {
    return { ok: true, verifier: decryptSecret(stored, getConfig().encryptionKey) };
  } catch {
    return { ok: false, reason: 'undecryptable' };
  }
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
    `SELECT live.expires_at AS live_expires_at,
            (live.expires_at <= now()) AS live_is_expired,
            receipt.state AS receipt_state,
            receipt.expires_at AS receipt_expires_at
       FROM (SELECT 1) AS anchor
       LEFT JOIN LATERAL (
         SELECT s.expires_at FROM secrets s WHERE s.control_hash = $1
       ) AS live ON true
       LEFT JOIN LATERAL (
         SELECT r.state, r.expires_at FROM secret_receipts r WHERE r.control_hash = $1
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
    };
  }
  if (row.receipt_state) {
    return { state: row.receipt_state, expiresAt: row.receipt_expires_at };
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
 * Sequence: read the row without a lock, verify the password outside any
 * transaction, decrypt the outer layer that was just read, and only then attempt
 * the atomic conditional delete that also writes the close receipt.
 *
 * Decryption comes before the delete on purpose. A wrong key or a corrupted
 * ciphertext makes the GCM tag fail, and deleting first would destroy a secret
 * that nobody has read yet. A failure here is reported as `undecryptable` and
 * the row is left in place: restoring the key makes the link work again.
 *
 * A failing password never reaches the decrypt or the delete, so it cannot
 * consume the secret.
 */
export async function revealSecret(token: string, revealProof?: string): Promise<RevealResult> {
  if (!isValidTokenShape(token)) return { ok: false, reason: 'unavailable' };

  const tokenHash = hashToken(token);

  const { rows: candidates } = await query<SecretRow>(
    `SELECT ciphertext, password_hash, password_verifier, reveal_proof_hash
       FROM secrets
      WHERE token_hash = $1
        AND expires_at > now()`,
    [tokenHash],
  );
  const candidate = candidates[0];
  if (!candidate) return { ok: false, reason: 'unavailable' };
  if (candidate.password_hash !== null ||
      (candidate.password_verifier === null) !== (candidate.reveal_proof_hash === null)) {
    return { ok: false, reason: 'unavailable' };
  }

  // A v2 verifier seals a random proof under the password-derived key. Only
  // its hash is stored here; possession of the share token alone is insufficient.
  if (candidate.reveal_proof_hash !== null) {
    if (typeof revealProof !== 'string' || !isValidTokenShape(revealProof) ||
        !timingSafeEqual(Buffer.from(hashToken(revealProof), 'hex'), Buffer.from(candidate.reveal_proof_hash, 'hex'))) {
      return { ok: false, reason: 'bad_password' };
    }
  }

  // A wrong key or a tampered payload lands here. Nothing is logged: the
  // ciphertext, the token, the password and the payload are all off limits.
  let payload: string;
  try {
    payload = decryptSecret(candidate.ciphertext, getConfig().encryptionKey);
  } catch {
    return { ok: false, reason: 'undecryptable' };
  }

  const consumed = await withClient(async (client) => {
    await client.query('BEGIN');
    try {
      const { rows } = await client.query<ConsumedRow>(
        `DELETE FROM secrets
          WHERE token_hash = $1
            AND expires_at > now()
            AND reveal_proof_hash IS NOT DISTINCT FROM $2::text
          RETURNING ciphertext, control_hash, expires_at`,
        [tokenHash, candidate.reveal_proof_hash],
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

  if (consumed.ciphertext !== candidate.ciphertext) {
    // Unreachable today: the delete is the only writer of this column and
    // nothing updates it in place, so the two values are always the same string.
    // The row is gone either way, so refusing here would report a consumed
    // secret as unavailable and destroy it. The deleted payload is the one this
    // caller has just consumed, so decrypt that instead of discarding it.
    try {
      return { ok: true, payload: decryptSecret(consumed.ciphertext, getConfig().encryptionKey) };
    } catch {
      return { ok: false, reason: 'undecryptable' };
    }
  }

  return { ok: true, payload };
}

/**
 * Remove expired secrets, write their receipts, drop spent receipts and stale
 * rate limit counters.
 *
 * The receipt insert runs in the same statement as the delete so an expired row
 * and the record that explains its control link appear together. `ON CONFLICT`
 * is allowed only here: this is a maintenance job that must not fail wholesale,
 * and a collision there can only mean a 256-bit token repeated.
 *
 * The counts reported are the rows each statement deleted: expired secrets, spent
 * receipts and idle counters. Receipts written by the first statement are not
 * counted, because a maintenance report is about what was removed.
 */
export async function purgeExpired(
  olderThanSeconds: number,
): Promise<{ secrets: number; receipts: number; counters: number }> {
  const removed = await query<{ secrets: string; receipts: string }>(
    `WITH deleted AS (
       DELETE FROM secrets WHERE expires_at <= now()
       RETURNING control_hash, expires_at
     ), receipts AS (
       INSERT INTO secret_receipts (control_hash, state, expires_at, closed_at, purge_after)
       SELECT control_hash,
              'expired',
              expires_at,
              now(),
              GREATEST(expires_at, now() + make_interval(days => $1::int))
         FROM deleted
        WHERE control_hash IS NOT NULL
       ON CONFLICT (control_hash) DO NOTHING
       RETURNING 1
     )
     SELECT (SELECT count(*) FROM deleted)::text AS secrets,
            (SELECT count(*) FROM receipts)::text AS receipts`,
    [RECEIPT_RETENTION_DAYS],
  );
  const receipts = await query<{ count: string }>(
    `WITH deleted AS (
       DELETE FROM secret_receipts WHERE purge_after <= now() RETURNING 1
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
    secrets: Number.parseInt(removed.rows[0]?.secrets ?? '0', 10),
    receipts: Number.parseInt(receipts.rows[0]?.count ?? '0', 10),
    counters: Number.parseInt(counters.rows[0]?.count ?? '0', 10),
  };
}
