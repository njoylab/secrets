/**
 * Periodic maintenance SQL, the single implementation behind `npm run cleanup`.
 *
 * Plain ESM JavaScript on purpose: `scripts/cleanup.mjs` is a Node script and
 * cannot import TypeScript, while the test suite imports this same module, so
 * what the tests prove is what production runs.
 *
 * Deleting a row removes it from the heap, but PostgreSQL may still retain old
 * copies in WAL, in free space maps, or in base backups. Application-level
 * deletion is not guaranteed erasure.
 */

/** Days a close receipt outlives the secret it describes. */
export const RECEIPT_RETENTION_DAYS = 7;

/**
 * Delete expired secrets and write their receipts, then drop spent receipts and
 * rate limit counters whose window started more than `counterRetentionSeconds`
 * ago. Each statement commits on its own.
 *
 * The receipt is written in the same statement as the delete, so an expired row
 * and the record its control link shows never exist apart. ON CONFLICT is
 * accepted only here: this job must not fail wholesale, and a collision can only
 * mean a 256-bit token repeated.
 *
 * `secrets`, `receipts` and `counters` count deleted rows; `receiptsWritten`
 * counts the `expired` receipts the first statement inserted.
 *
 * @param {{ query: (text: string, values?: unknown[]) => Promise<{ rows: any[] }> }} db
 * @param {number} counterRetentionSeconds
 * @returns {Promise<{ secrets: number, receiptsWritten: number, receipts: number, counters: number }>}
 */
export async function purgeExpired(db, counterRetentionSeconds) {
  const secrets = await db.query(
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
     SELECT (SELECT count(*) FROM deleted)::int AS secrets,
            (SELECT count(*) FROM receipts)::int AS receipts`,
    [RECEIPT_RETENTION_DAYS],
  );
  const receipts = await db.query(
    `WITH deleted AS (DELETE FROM secret_receipts WHERE purge_after <= now() RETURNING 1)
     SELECT count(*)::int AS count FROM deleted`,
  );
  const counters = await db.query(
    `WITH deleted AS (
       DELETE FROM rate_limits
        WHERE window_started_at <= now() - make_interval(secs => $1::double precision)
        RETURNING 1
     )
     SELECT count(*)::int AS count FROM deleted`,
    [counterRetentionSeconds],
  );

  return {
    secrets: secrets.rows[0]?.secrets ?? 0,
    receiptsWritten: secrets.rows[0]?.receipts ?? 0,
    receipts: receipts.rows[0]?.count ?? 0,
    counters: counters.rows[0]?.count ?? 0,
  };
}
