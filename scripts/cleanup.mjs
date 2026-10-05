#!/usr/bin/env node
/**
 * Periodic maintenance: delete expired secrets, write their close receipts,
 * drop spent receipts and idle rate limit counters.
 *
 * Deleting a row here removes it from the heap, but PostgreSQL may still retain
 * old copies in WAL, in free space maps, or in base backups. Application-level
 * deletion is not guaranteed erasure.
 */
import pg from 'pg';
import { counterRetention, parseSeconds } from '../src/lib/retention.mjs';

/** Days a close receipt outlives the secret it describes. */
const RECEIPT_RETENTION_DAYS = 7;

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) fail('DATABASE_URL is required');

// The operator's own setting is validated loudly, with the very parser that
// counterRetention() reads it with, so a malformed value cannot pass the check
// here and then be silently replaced by the default further down.
const rawRetention = process.env.CLEANUP_KEEP_COUNTER_SECONDS;
if (rawRetention !== undefined && rawRetention.trim() !== '') {
  if (parseSeconds(rawRetention) === undefined) {
    fail('CLEANUP_KEEP_COUNTER_SECONDS must be a non-negative integer');
  }
}

// A counter is keyed by the start of its window: dropping one whose window is
// still open would hand that subject a fresh budget, so the configured retention
// is raised to the longest rate limit window.
const { configuredSeconds, effectiveSeconds } = counterRetention(process.env);

const client = new pg.Client({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 10_000,
  options: '-c statement_timeout=60000 -c lock_timeout=5000',
});
await client.connect();

try {
  // The receipt is written in the same statement as the delete, so an expired
  // row and the record its control link shows never exist apart. ON CONFLICT is
  // accepted only here: this job must not fail wholesale, and a collision can
  // only mean a 256-bit token repeated.
  const secrets = await client.query(
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
  const receipts = await client.query(
    `WITH deleted AS (DELETE FROM secret_receipts WHERE purge_after <= now() RETURNING 1)
     SELECT count(*)::int AS count FROM deleted`,
  );
  const counters = await client.query(
    `WITH deleted AS (
       DELETE FROM rate_limits
        WHERE window_started_at <= now() - make_interval(secs => $1::double precision)
        RETURNING 1
     )
     SELECT count(*)::int AS count FROM deleted`,
    [effectiveSeconds],
  );

  const secretCount = secrets.rows[0]?.secrets ?? 0;
  const receiptWritten = secrets.rows[0]?.receipts ?? 0;
  const receiptCount = receipts.rows[0]?.count ?? 0;
  const counterCount = counters.rows[0]?.count ?? 0;
  process.stdout.write(
    `removed ${secretCount} expired secret(s), wrote ${receiptWritten} receipt(s), ` +
      `removed ${receiptCount} spent receipt(s) and ${counterCount} idle counter(s)\n`,
  );
  if (effectiveSeconds > configuredSeconds) {
    process.stdout.write(
      `counter retention raised to ${effectiveSeconds}s: CLEANUP_KEEP_COUNTER_SECONDS is ${configuredSeconds}s, ` +
        'shorter than a rate limit window, which would reset the budget of a subject whose window is still open\n',
    );
  }
} finally {
  await client.end();
}
