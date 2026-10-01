#!/usr/bin/env node
/**
 * Periodic maintenance: delete expired secrets and idle rate limit counters.
 *
 * Deleting a row here removes it from the heap, but PostgreSQL may still retain
 * old copies in WAL, in free space maps, or in base backups. Application-level
 * deletion is not guaranteed erasure.
 */
import pg from 'pg';
import { counterRetention, parseSeconds } from '../src/lib/retention.mjs';

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
    [effectiveSeconds],
  );

  const secretCount = secrets.rows[0]?.count ?? 0;
  const counterCount = counters.rows[0]?.count ?? 0;
  process.stdout.write(
    `removed ${secretCount} expired secret(s) and ${counterCount} idle counter(s)\n`,
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
