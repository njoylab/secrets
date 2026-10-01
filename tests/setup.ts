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

function databaseName(url: string): string {
  return decodeURIComponent(new URL(url).pathname).replace(/^\//, '');
}

/** The suite truncates tables, so refuse anything that is not obviously a test database. */
function assertIsolatedDatabase(url: string): void {
  const name = databaseName(url);
  if (!name.endsWith('_test')) {
    throw new Error(
      `Refusing to run the test suite against database "${name}": ` +
        'set DATABASE_URL to a *_test database (see .env.test).',
    );
  }
}

/**
 * Apply environment overrides, drop the memoized configuration and empty both
 * tables so a test never observes rows from another test.
 */
export async function resetEnv(
  overrides: Readonly<Record<string, string | undefined>> = {},
): Promise<void> {
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  resetConfigCache();
  await query('DELETE FROM secrets');
  await query('DELETE FROM rate_limits');
}

beforeAll(async () => {
  if (!process.env.DATABASE_URL) process.env.DATABASE_URL = TEST_DATABASE_URL;
  assertIsolatedDatabase(process.env.DATABASE_URL ?? TEST_DATABASE_URL);

  // A fresh key per run: the suite must never read or write the developer's key.
  process.env.SECRET_ENCRYPTION_KEY = randomBytes(32).toString('base64url');
  process.env.RATE_LIMIT_CREATE_MAX = '5';
  process.env.RATE_LIMIT_CREATE_WINDOW_SECONDS = '3600';
  process.env.RATE_LIMIT_REVEAL_MAX = '5';
  process.env.RATE_LIMIT_REVEAL_WINDOW_SECONDS = '300';
  // Heredity from a developer shell must not change what the assertions mean.
  delete process.env.TRUSTED_PROXIES;
  delete process.env.ALLOWED_ORIGINS;

  await resetEnv();
});

afterAll(async () => {
  await resetEnv();
  await closePool();
});
