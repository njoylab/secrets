import { it } from 'vitest';
import { query } from '../../src/lib/db.ts';

// Keep an existing pool to detect teardown queries after configuration rejection.
await query('SELECT 1');
const rejected = new URL(process.env.DATABASE_URL!);
rejected.pathname = '/rejected_database';
process.env.DATABASE_URL = rejected.toString();

it('never reaches the test after rejecting the database', () => {
  throw new Error('The database guard should have stopped this test');
});
