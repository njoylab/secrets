/**
 * Vitest global setup.
 *
 * Responsibilities: point the suite at the isolated test database, install an
 * ephemeral encryption key so nothing depends on the developer's `.env`, keep
 * the rate limits small enough for a fast run, and own the database lifecycle.
 *
 * Vitest isolates module registries per test file, so the hooks below run once
 * per file and the exported `resetEnv` helper re-applies that environment after
 * a test has overridden it.
 */
import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll } from 'vitest';
import { closePool, query } from '../src/lib/db.ts';
import { resetConfigCache } from '../src/lib/env.ts';

const TEST_DATABASE_URL = 'postgres://postgres:postgres@localhost:5433/secrets_test';
let authorizedDatabaseUrl: string | undefined;

/** The suite truncates tables, so refuse anything that is not obviously a test database. */
function assertIsolatedDatabase(url: string): void {
  const database = new URL(url);
  const name = decodeURIComponent(database.pathname).replace(/^\//, '');
  if (!['postgres:', 'postgresql:'].includes(database.protocol) ||
      !['localhost', '127.0.0.1', '[::1]'].includes(database.hostname) ||
      database.search || !name.endsWith('_test')) {
    throw new Error(
      `Refusing to run the test suite against database "${name}": ` +
        'set DATABASE_URL to a local *_test database without query parameters (see .env.test).',
    );
  }
}

/**
 * Apply environment overrides, drop the memoized configuration and empty every
 * table the suite writes, so a test never observes rows from another test.
 *
 * Receipts are cleared alongside the secrets they describe: a leftover receipt
 * would answer for a control token the next test just created.
 */
export async function resetEnv(
  overrides: Readonly<Record<string, string | undefined>> = {},
): Promise<void> {
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  // Teardown runs even when beforeAll rejects the target. Never trust hook ordering.
  const databaseUrl = process.env.DATABASE_URL;
  if (!authorizedDatabaseUrl || databaseUrl !== authorizedDatabaseUrl) {
    throw new Error('Refusing database cleanup without the authorized test database');
  }
  assertIsolatedDatabase(databaseUrl);
  resetConfigCache();
  await query('DELETE FROM secret_receipts');
  await query('DELETE FROM secrets');
  await query('DELETE FROM rate_limits');
}

beforeAll(async () => {
  if (!process.env.DATABASE_URL) process.env.DATABASE_URL = TEST_DATABASE_URL;
  assertIsolatedDatabase(process.env.DATABASE_URL ?? TEST_DATABASE_URL);
  authorizedDatabaseUrl = process.env.DATABASE_URL;

  // A fresh key per run: the suite must never read or write the developer's key.
  process.env.SECRET_ENCRYPTION_KEY = randomBytes(32).toString('base64url');
  process.env.RATE_LIMIT_CREATE_MAX = '5';
  process.env.RATE_LIMIT_CREATE_WINDOW_SECONDS = '3600';
  process.env.RATE_LIMIT_REVEAL_MAX = '5';
  process.env.RATE_LIMIT_REVEAL_WINDOW_SECONDS = '300';
  // Heredity from a developer shell must not change what the assertions mean.
  delete process.env.TRUSTED_PROXIES;
  delete process.env.ALLOWED_ORIGINS;
  delete process.env.SOURCE_URL;

  await resetEnv();
});

afterAll(async () => {
  try {
    if (authorizedDatabaseUrl) await resetEnv();
  } finally {
    await closePool();
  }
});
