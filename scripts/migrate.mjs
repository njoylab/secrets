#!/usr/bin/env node
/**
 * Applies every unapplied migration from ./migrations in filename order.
 *
 * Each file runs inside its own transaction and is recorded in
 * schema_migrations, so re-running is a no-op and a failed migration rolls back
 * without leaving a partial version marker.
 */
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) fail('DATABASE_URL is required');

const client = new pg.Client({ connectionString: databaseUrl, connectionTimeoutMillis: 10_000 });
await client.connect();

try {
  // Serialize deploys before reading the applied versions.
  await client.query("SET statement_timeout = '60s'");
  await client.query('SELECT pg_advisory_lock(731824991)');
  await client.query(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text        PRIMARY KEY,
        applied_at timestamptz NOT NULL DEFAULT now()
    )
  `);

  const { rows: appliedRows } = await client.query('SELECT version FROM schema_migrations');
  const applied = new Set(appliedRows.map((row) => row.version));

  const files = (await readdir(MIGRATIONS_DIR))
    .filter((name) => name.endsWith('.sql'))
    .sort((a, b) => a.localeCompare(b, 'en'));

  let count = 0;
  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = await readFile(join(MIGRATIONS_DIR, file), 'utf8');
    try {
      await client.query('BEGIN');
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations (version) VALUES ($1)', [file]);
      await client.query('COMMIT');
      process.stdout.write(`applied ${file}\n`);
      count += 1;
    } catch {
      await client.query('ROLLBACK');
      process.stderr.write(`failed ${file}; transaction rolled back\n`);
      process.exit(1);
    }
  }

  process.stdout.write(count === 0 ? 'database already up to date\n' : `${count} migration(s) applied\n`);
} finally {
  await client.end();
}
