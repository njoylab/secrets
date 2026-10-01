#!/usr/bin/env node
/**
 * Periodic maintenance: delete expired secrets and idle rate limit counters.
 *
 * Deleting a row here removes it from the heap, but PostgreSQL may still retain
 * old copies in WAL, in free space maps, or in base backups. Application-level
 * deletion is not guaranteed erasure.
 */
import pg from 'pg';

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) fail('DATABASE_URL is required');

const rawRetention = process.env.CLEANUP_KEEP_COUNTER_SECONDS ?? '3600';
const keepCounterSeconds = Number.parseInt(rawRetention, 10);
if (!Number.isSafeInteger(keepCounterSeconds) || keepCounterSeconds < 0) {
  fail('CLEANUP_KEEP_COUNTER_SECONDS must be a non-negative integer');
}

const client = new pg.Client({ connectionString: databaseUrl });
await client.connect();

try {
  const secrets = await client.query(
    `WITH deleted AS (DELETE FROM secrets WHERE expires_at <= now() RETURNING 1)
     SELECT count(*)::int AS count FROM deleted`,
  );
  const counters = await client.query(
    `WITH deleted AS (
       DELETE FROM rate_limits
        WHERE window_started_at <= now() - make_interval(secs => $1::double precision)
        RETURNING 1
     )
     SELECT count(*)::int AS count FROM deleted`,
    [keepCounterSeconds],
  );

  const secretCount = secrets.rows[0]?.count ?? 0;
  const counterCount = counters.rows[0]?.count ?? 0;
  process.stdout.write(
    `removed ${secretCount} expired secret(s) and ${counterCount} idle counter(s)\n`,
  );
} finally {
  await client.end();
}