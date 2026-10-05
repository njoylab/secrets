/**
 * Single shared connection pool. A process-wide pool keeps connection churn
 * out of request handling while still allowing tests to reset it.
 */
import pg from 'pg';
import { getConfig } from './env.ts';

const { Pool } = pg;

let pool: pg.Pool | undefined;

export function getPool(): pg.Pool {
  if (!pool) {
    pool = new Pool({
      connectionString: getConfig().databaseUrl,
      max: 10,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 10_000,
      // Keep numeric/date columns as strings unless explicitly cast, to avoid
      // silent precision loss and timezone drift in expiry comparisons.
      options: '-c timezone=UTC -c statement_timeout=10000 -c lock_timeout=5000',
    });
    pool.on('error', () => {
      // Idle client errors are recoverable: the pool discards the client.
    });
  }
  return pool;
}

export async function query<Row extends pg.QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<pg.QueryResult<Row>> {
  return getPool().query<Row>(text, params as unknown[]);
}

/** Run `fn` with a dedicated client from the pool. Never holds it across slow crypto work. */
export async function withClient<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect();
  try {
    return await fn(client);
  } finally {
    client.release();
  }
}

export async function closePool(): Promise<void> {
  if (!pool) return;
  const closing = pool;
  pool = undefined;
  await closing.end();
}
