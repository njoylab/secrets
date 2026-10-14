#!/usr/bin/env node
/**
 * Periodic maintenance: delete expired secrets, write their close receipts,
 * drop spent receipts and idle rate limit counters. The SQL lives in
 * `src/lib/cleanup.mjs`, which the test suite exercises directly.
 */
import pg from 'pg';
import { purgeExpired } from '../src/lib/cleanup.mjs';
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

const client = new pg.Client({
  connectionString: databaseUrl,
  connectionTimeoutMillis: 10_000,
  options: '-c statement_timeout=60000 -c lock_timeout=5000',
});
await client.connect();

try {
  const result = await purgeExpired(client, effectiveSeconds);
  process.stdout.write(
    `removed ${result.secrets} expired secret(s), wrote ${result.receiptsWritten} receipt(s), ` +
      `removed ${result.receipts} spent receipt(s) and ${result.counters} idle counter(s)\n`,
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
