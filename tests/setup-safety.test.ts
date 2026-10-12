import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { expect, it } from 'vitest';
import { createSecret } from '../src/lib/secrets.ts';
import { fetchSecretRow, sealedSecret } from './helpers.ts';

const run = promisify(execFile);

it('never deletes existing rows during teardown after rejecting the database', async () => {
  const created = await createSecret({ payload: (await sealedSecret('synthetic guard fixture')).payload, expiresIn: '1h' });
  const directory = await mkdtemp(join(tmpdir(), 'secrets-test-guard-'));
  try {
    const config = join(directory, 'vitest.config.mjs');
    await writeFile(config, `export default ${JSON.stringify({
      test: {
        include: [resolve('tests/fixtures/rejected-database.ts')],
        setupFiles: [resolve('tests/setup.ts')],
        fileParallelism: false,
      },
    })};`);
    const result = await run(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', '--config', config], {
      env: { ...process.env },
      timeout: 15_000,
    }).then(
      () => ({ rejected: false, output: '' }),
      (error: { stdout?: string; stderr?: string }) => ({ rejected: true, output: `${error.stdout ?? ''}${error.stderr ?? ''}` }),
    );
    expect(result.rejected).toBe(true);
    expect(result.output).toContain('Refusing to run the test suite');
    expect(await fetchSecretRow(created.token)).toBeDefined();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
